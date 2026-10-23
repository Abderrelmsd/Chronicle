using System.Data.Common;
using System.Text.Json;
using Bedrock;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;

namespace Chronicle;

/// <summary>
/// Audit inside the caller's business transaction without making it wait for the chain: the record (validated, its personal data already
/// encrypted) goes to the pending table with the change, and commits or rolls back with it. <see cref="IChronicleIngestor"/> links pending
/// records into their chains, in order, moments later, so business writes of one tenant never queue behind its chain head.
/// </summary>
public interface IChronicleOutbox
{
    /// <summary>Records for the current tenant's chain on <paramref name="connection"/> and <paramref name="transaction"/>. Returns the entry id.</summary>
    Task<Guid> RecordInTransactionAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, AuditRecord record, CancellationToken cancellationToken = default);
}

/// <summary>Moves pending records into their chains: one ingester per cluster at a time (an advisory lock), re-runnable after a crash.</summary>
public interface IChronicleIngestor
{
    /// <summary>One pass over every cluster's pending table; returns how many records were linked.</summary>
    Task<int> IngestOnceAsync(CancellationToken cancellationToken = default);
}

/// <summary>The pending table's DDL and row-level security.</summary>
public static class ChroniclePending
{
    public const string DefaultTable = "chronicle_pending";

    /// <summary>
    /// The pending table, with row-level security so tenant transactions add only their own records. <paramref name="setting"/> and
    /// <paramref name="role"/> are the product's Bedrock tenant setting and application role.
    /// </summary>
    public static string SchemaSql(string table = DefaultTable, string schema = "public", string setting = RlsConvention.DefaultSetting, string? role = null) => $"""
        CREATE TABLE IF NOT EXISTS "{schema}"."{table}" (
          id          uuid        PRIMARY KEY,
          tenant_id   text        NOT NULL,
          created_at  timestamptz NOT NULL,
          sequence    bigint      GENERATED ALWAYS AS IDENTITY,
          entry       jsonb       NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_{table}_order ON "{schema}"."{table}" (sequence);
        {BedrockMigrationExtensions.EnableTenantRlsSql(table, schema, RlsConvention.DefaultColumn, setting, TenantKeyType.Text, role)}
        """;
}

internal sealed class ChronicleOutbox(ChronicleService chronicle, IOptions<ChronicleOptions> options, TimeProvider time) : IChronicleOutbox
{
    public async Task<Guid> RecordInTransactionAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, AuditRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var prepared = await chronicle.PrepareAsync(record, ct);
        if (prepared.Chain == ChronicleConstants.SystemChain) throw new TenantContextMissingException();
        await using var cmd = new NpgsqlCommand(
            $"INSERT INTO {options.Value.PendingTableSql} (id, tenant_id, created_at, entry) VALUES (@id, @tenant, @at, @entry)", connection, transaction);
        cmd.Parameters.AddWithValue("id", prepared.Id);
        cmd.Parameters.AddWithValue("tenant", prepared.Chain);
        cmd.Parameters.AddWithValue("at", time.GetUtcNow());
        cmd.Parameters.Add(new NpgsqlParameter("entry", NpgsqlDbType.Jsonb) { Value = PendingJson.Write(prepared) });
        await cmd.ExecuteNonQueryAsync(ct);
        return prepared.Id;
    }
}

internal sealed class ChronicleIngestor(
    ChronicleService chronicle,
    IChronicleStore store,
    IBedrockDataSources sources,
    ITenantContextAccessor tenants,
    IOptions<ChronicleOptions> options,
    ILogger<ChronicleIngestor> logger) : IChronicleIngestor
{
    // One ingester per cluster at a time keeps each chain's records in their committed order.
    private const long LockKey = 0x4368726F6E69636CL;

    public async Task<int> IngestOnceAsync(CancellationToken ct = default)
    {
        var total = 0;
        foreach (var cluster in sources.ClusterIds)
        {
            if (sources.System(cluster) is not { } system) continue;
            total += await IngestClusterAsync(system, ct);
        }

        return total;
    }

    private async Task<int> IngestClusterAsync(NpgsqlDataSource system, CancellationToken ct)
    {
        await using var connection = await system.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var locked = new NpgsqlCommand("SELECT pg_try_advisory_xact_lock(@key)", connection, transaction))
        {
            locked.Parameters.AddWithValue("key", LockKey);
            if (!(bool)(await locked.ExecuteScalarAsync(ct))!) return 0;
        }

        var pending = new List<(Guid Id, string Tenant, PreparedEntry Entry)>();
        await using (var select = new NpgsqlCommand(
            $"SELECT id, tenant_id, entry FROM {options.Value.PendingTableSql} ORDER BY sequence LIMIT @take", connection, transaction))
        {
            select.Parameters.AddWithValue("take", options.Value.IngestBatchSize);
            await using var reader = await select.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) pending.Add((reader.GetGuid(0), reader.GetString(1), PendingJson.Read(reader.GetString(2))));
        }

        foreach (var (id, tenant, entry) in pending)
        {
            using (tenants.Use(tenant))
            {
                // A run that crashed after appending but before deleting appended it already: the id says so.
                if (!await store.ContainsAsync(entry.Chain, id, ct)) await chronicle.AppendAsync(entry, ct);
            }
        }

        if (pending.Count > 0)
        {
            await using var delete = new NpgsqlCommand($"DELETE FROM {options.Value.PendingTableSql} WHERE id = ANY(@ids)", connection, transaction);
            delete.Parameters.AddWithValue("ids", pending.Select(p => p.Id).ToArray());
            await delete.ExecuteNonQueryAsync(ct);
        }

        await transaction.CommitAsync(ct);
        if (pending.Count > 0) logger.LogDebug("Linked {Count} pending audit records", pending.Count);
        return pending.Count;
    }
}

/// <summary>Runs the ingester in the background, pausing when nothing is pending.</summary>
internal sealed class ChronicleIngestorService(IChronicleIngestor ingestor, IOptions<ChronicleOptions> options, ILogger<ChronicleIngestorService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var linked = 0;
            try { linked = await ingestor.IngestOnceAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogError(ex, "Chronicle ingest pass failed"); }
            if (linked == 0)
                try { await Task.Delay(options.Value.IngestInterval, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}

internal static class PendingJson
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private sealed record Row(Guid Id, string Chain, DateTimeOffset OccurredAt, string Action, string? EntityType, string? EntityId, string? Actor, string? SubjectId,
        string DataJson, Dictionary<string, string> Pii);

    public static string Write(PreparedEntry e) => JsonSerializer.Serialize(
        new Row(e.Id, e.Chain, e.OccurredAt, e.Action, e.EntityType, e.EntityId, e.Actor, e.SubjectId, e.DataJson,
            e.Pii.ToDictionary(kv => kv.Key, kv => Convert.ToBase64String(kv.Value.Envelope))), Json);

    public static PreparedEntry Read(string json)
    {
        var r = JsonSerializer.Deserialize<Row>(json, Json) ?? throw new ChronicleException("Unreadable pending record.");
        return new PreparedEntry(r.Id, r.Chain, r.OccurredAt, r.Action, r.EntityType, r.EntityId, r.Actor, r.SubjectId, r.DataJson,
            r.Pii.ToDictionary(kv => kv.Key, kv => new EncryptedField(Convert.FromBase64String(kv.Value))));
    }
}
