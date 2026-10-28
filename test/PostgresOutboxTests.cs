using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Bedrock;
using Chronicle.Data;
using Cipher;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Chronicle.Tests;

public sealed class PgFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _c;
    public bool Available { get; private set; }
    public string Reason { get; private set; } = "Docker/Postgres unavailable";
    public string AdminCs { get; private set; } = "";
    public string LoginCs { get; private set; } = "";

    public async ValueTask InitializeAsync()
    {
        try
        {
            _c = new PostgreSqlBuilder("postgres:17-alpine").Build();
            await _c.StartAsync();
            AdminCs = _c.GetConnectionString();
            using var design = new ChronicleDb(new DbContextOptionsBuilder<ChronicleDb>().UseNpgsql(AdminCs).Options, FixedTenantContext.System);
            await using var admin = new NpgsqlConnection(AdminCs);
            await admin.OpenAsync();
            foreach (var sql in new[]
            {
                "CREATE ROLE app_rls NOLOGIN NOBYPASSRLS",
                "CREATE ROLE app_login LOGIN PASSWORD 'login' NOBYPASSRLS NOINHERIT",
                "GRANT app_rls TO app_login",
                design.GenerateSchemaScript(),
                ChroniclePending.SchemaSql(),
                "GRANT SELECT, INSERT, UPDATE ON chronicle_entries TO app_rls",
                "GRANT INSERT ON chronicle_pending TO app_rls",
            })
            {
                await using var cmd = new NpgsqlCommand(sql, admin);
                await cmd.ExecuteNonQueryAsync();
            }

            LoginCs = new NpgsqlConnectionStringBuilder(AdminCs) { Username = "app_login", Password = "login" }.ConnectionString;
            Available = true;
        }
        catch (Exception ex) { Reason = "Docker/Postgres unavailable: " + ex.GetType().Name + ": " + ex.Message; }
    }

    public async ValueTask DisposeAsync()
    {
        if (_c is not null) await _c.DisposeAsync();
    }
}

/// <summary>
/// The transactional outbox against Postgres, in Bedrock's transaction scope: records written with a business transaction reach the chain
/// only if it commits, in order, with their personal data still encrypted, and a crashed ingest does not append twice.
/// </summary>
public class PostgresOutboxTests(PgFixture pg) : IClassFixture<PgFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private ServiceProvider Build(Action<ChronicleOptions>? configure = null)
    {
        var s = new ServiceCollection();
        s.AddLogging();
        s.AddCipher();
        s.AddBedrock(o =>
        {
            o.ConnectionString = pg.LoginCs;
            o.SystemConnectionString = pg.AdminCs;
            o.TenantScope = TenantScope.Transaction;
            o.ApplicationRole = "app_rls";
        });
        s.AddChronicleBedrockSessions();
        s.AddChronicle(configure);
        return s.BuildServiceProvider();
    }

    private static AuditRecord Record(string action, string? email = null, DateTimeOffset? occurredAt = null) => new()
    {
        OccurredAt = occurredAt,
        Action = action, EntityType = "invoice", EntityId = "A-1", Actor = "u1", Data = new JsonObject { ["total"] = 12.5 },
        Pii = email is null ? null : new Dictionary<string, string> { ["email"] = email }, SubjectId = email is null ? null : "customer-1",
    };

    [Fact]
    public async Task Times_finer_than_a_microsecond_still_verify_after_a_round_trip()
    {
        Assert.SkipUnless(pg.Available, pg.Reason);
        await using var sp = Build();
        var tenants = sp.GetRequiredService<ITenantContextAccessor>();
        var tenant = "t" + Guid.NewGuid().ToString("N")[..8];
        // Linux clocks produce sub-microsecond ticks; Postgres keeps microseconds. The hash must be of the stored value.
        var at = new DateTimeOffset(2026, 10, 24, 13, 0, 0, TimeSpan.FromHours(2)).AddTicks(1_234_567);

        using (tenants.Use(tenant))
        {
            var chronicle = sp.GetRequiredService<IChronicle>();
            await chronicle.RecordAsync(Record("invoice.saved", occurredAt: at), Ct);

            var connections = sp.CreateScope().ServiceProvider.GetRequiredService<IBedrockConnectionFactory>();
            await using var connection = await connections.OpenTenantConnectionAsync(Ct);
            await using var tx = await connections.BeginTenantTransactionAsync(connection, cancellationToken: Ct);
            await sp.GetRequiredService<IChronicleOutbox>().RecordInTransactionAsync(connection, tx, Record("invoice.issued", occurredAt: at), Ct);
            await tx.CommitAsync(Ct);
        }
        Assert.Equal(1, await sp.GetRequiredService<IChronicleIngestor>().IngestOnceAsync(Ct));

        using (tenants.Use(tenant))
        {
            var chronicle = sp.GetRequiredService<IChronicle>();
            var verification = await chronicle.VerifyAsync(cancellationToken: Ct);
            Assert.True(verification.IsValid, verification.Reason);
            Assert.All(await chronicle.QueryAsync(cancellationToken: Ct), e => Assert.Equal(at.UtcTicks - at.UtcTicks % 10, e.OccurredAt.UtcTicks));
        }
    }

    [Fact]
    public async Task Records_reach_the_chain_only_with_a_commit_in_order_and_once()
    {
        Assert.SkipUnless(pg.Available, pg.Reason);
        await using var sp = Build();
        var tenants = sp.GetRequiredService<ITenantContextAccessor>();
        var outbox = sp.GetRequiredService<IChronicleOutbox>();
        var connections = sp.CreateScope().ServiceProvider.GetRequiredService<IBedrockConnectionFactory>();
        var tenant = "t" + Guid.NewGuid().ToString("N")[..8];
        Guid issued;

        using (tenants.Use(tenant))
        {
            await using var connection = await connections.OpenTenantConnectionAsync(Ct);
            await using (var rolledBack = await connections.BeginTenantTransactionAsync(connection, cancellationToken: Ct))
            {
                await outbox.RecordInTransactionAsync(connection, rolledBack, Record("invoice.drafted"), Ct);
            }

            await using var committed = await connections.BeginTenantTransactionAsync(connection, cancellationToken: Ct);
            await outbox.RecordInTransactionAsync(connection, committed, Record("invoice.saved"), Ct);
            issued = await outbox.RecordInTransactionAsync(connection, committed, Record("invoice.issued", "ada@example.test"), Ct);
            await committed.CommitAsync(Ct);
        }

        var ingestor = sp.GetRequiredService<IChronicleIngestor>();
        Assert.Equal(2, await ingestor.IngestOnceAsync(Ct));
        Assert.Equal(0, await ingestor.IngestOnceAsync(Ct));

        // A run that appended but crashed before deleting: the record is back in the pending table.
        await using (var admin = new NpgsqlConnection(pg.AdminCs))
        {
            await admin.OpenAsync(Ct);
            await using var copy = new NpgsqlCommand(
                "INSERT INTO chronicle_pending (id, tenant_id, created_at, entry) SELECT id, tenant_id, now(), jsonb_build_object('id', id, 'chain', tenant_id, " +
                "'occurredAt', occurred_at, 'action', action, 'dataJson', data_json, 'pii', '{}'::jsonb) FROM chronicle_entries WHERE id = @id", admin);
            copy.Parameters.AddWithValue("id", issued);
            await copy.ExecuteNonQueryAsync(Ct);
        }

        Assert.Equal(1, await ingestor.IngestOnceAsync(Ct));

        using (tenants.Use(tenant))
        {
            var chronicle = sp.GetRequiredService<IChronicle>();
            var entries = await chronicle.QueryAsync(cancellationToken: Ct);
            Assert.Equal([(2L, "invoice.issued"), (1L, "invoice.saved")], entries.Select(e => (e.Sequence, e.Action)));
            Assert.True((await chronicle.VerifyAsync(cancellationToken: Ct)).IsValid);
            Assert.Equal("ada@example.test", Assert.Single(await chronicle.RevealAsync(entries[0], Ct)).Value);
        }

        using (tenants.Use("someone-else"))
        {
            Assert.Empty(await sp.GetRequiredService<IChronicle>().QueryAsync(cancellationToken: Ct));
        }
    }

    [Fact]
    public async Task Ingesting_everything_pending_passes_until_nothing_is_left()
    {
        Assert.SkipUnless(pg.Available, pg.Reason);
        await using var sp = Build(o => o.IngestBatchSize = 2);
        var tenants = sp.GetRequiredService<ITenantContextAccessor>();
        var outbox = sp.GetRequiredService<IChronicleOutbox>();
        var connections = sp.CreateScope().ServiceProvider.GetRequiredService<IBedrockConnectionFactory>();
        var tenant = "t" + Guid.NewGuid().ToString("N")[..8];
        using (tenants.Use(tenant))
        {
            await using var connection = await connections.OpenTenantConnectionAsync(Ct);
            await using var transaction = await connections.BeginTenantTransactionAsync(connection, cancellationToken: Ct);
            for (var i = 0; i < 5; i++) await outbox.RecordInTransactionAsync(connection, transaction, Record("invoice.saved"), Ct);
            await transaction.CommitAsync(Ct);
        }

        Assert.True(await sp.GetRequiredService<IChronicleIngestor>().IngestPendingAsync(Ct) >= 5);
        using (tenants.Use(tenant)) Assert.Equal(5, (await sp.GetRequiredService<IChronicle>().SummarizeAsync(cancellationToken: Ct)).Total);
    }
}
