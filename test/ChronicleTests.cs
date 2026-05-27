using System.Text;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Bedrock;
using Chronicle.Data;
using Cipher;
using Cipher.Keys;

namespace Chronicle.Tests;

public sealed class FakeTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class CapturingSink : IArchiveSink
{
    public List<(string Ref, IReadOnlyList<AuditEntry> Entries)> Written { get; } = [];
    public Task WriteAsync(string archiveRef, IReadOnlyList<AuditEntry> entries, CancellationToken ct = default) { Written.Add((archiveRef, entries)); return Task.CompletedTask; }
}

internal sealed class InMemoryDbFactory(InMemoryDatabaseRoot root, string name, ITenantContext ambient) : IChronicleDbFactory
{
    private ChronicleDb Make(ITenantContext t)
        => new(new DbContextOptionsBuilder<ChronicleDb>().UseInMemoryDatabase(name, root).AddInterceptors(new ChronicleImmutabilityInterceptor()).Options, t);
    public ChronicleDb CreateTenant() => Make(ambient);
    public ChronicleDb CreateSystem() => Make(FixedTenantContext.System);
}

public sealed class Env : IAsyncDisposable
{
    public FakeTime Time { get; } = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    public ServiceProvider Sp { get; }
    public IChronicle Chronicle => Sp.GetRequiredService<IChronicle>();
    public ITenantContextAccessor Tenants => Sp.GetRequiredService<ITenantContextAccessor>();
    public IKeyStore Keys => Sp.GetRequiredService<IKeyStore>();
    public IChronicleStore Store => Sp.GetRequiredService<IChronicleStore>();
    public CapturingSink Sink { get; } = new();

    public Env(bool ef = false, Action<ChronicleOptions>? configure = null)
    {
        var s = new ServiceCollection();
        s.AddLogging();
        s.AddSingleton<TimeProvider>(Time);
        s.AddCipher();
        var ambient = new AmbientTenantContext();
        s.AddSingleton(ambient);
        s.AddSingleton<ITenantContextAccessor>(ambient);
        s.AddSingleton<ITenantContext>(ambient);
        s.AddSingleton<IArchiveSink>(Sink);
        if (ef)
        {
            s.AddSingleton<IChronicleDbFactory>(new InMemoryDbFactory(new InMemoryDatabaseRoot(), Guid.NewGuid().ToString(), ambient));
            s.AddSingleton<IChronicleStore, EfChronicleStore>();
        }
        s.AddChronicle(configure);
        Sp = s.BuildServiceProvider();
    }

    public static AuditRecord Rec(string action = "order.updated", string? entityId = "o1", JsonObject? data = null, Dictionary<string, string>? pii = null, string? subject = null)
        => new() { Action = action, EntityType = "order", EntityId = entityId, Actor = "alice", Data = data ?? new JsonObject { ["status"] = "paid" }, Pii = pii, SubjectId = subject };

    public ValueTask DisposeAsync() => Sp.DisposeAsync();
}

public class ChronicleTests
{
    public static TheoryData<bool> Stores => new() { false, true }; // in-memory store and EF store

    [Theory, MemberData(nameof(Stores))]
    public async Task Entries_are_sequenced_hash_chained_sealed_and_verifiable(bool ef)
    {
        await using var env = new Env(ef);
        using var _ = env.Tenants.Use("acme");
        var a = await env.Chronicle.RecordAsync(Env.Rec());
        var b = await env.Chronicle.RecordAsync(Env.Rec("order.shipped"));

        Assert.Equal((1L, 2L), (a.Sequence, b.Sequence));
        Assert.Equal(new byte[32], a.PrevHash);
        Assert.Equal(a.Hash, b.PrevHash);
        Assert.NotEqual(a.Hash, b.Hash);
        Assert.NotEmpty(a.Seal);
        Assert.Equal("acme", a.Chain);

        var v = await env.Chronicle.VerifyAsync();
        Assert.True(v.IsValid, v.Reason);
        Assert.Equal(2, v.EntriesChecked);
    }

    [Fact]
    public async Task Tenants_have_independent_chains_and_cannot_reach_each_other()
    {
        await using var env = new Env();
        using (env.Tenants.Use("acme")) { await env.Chronicle.RecordAsync(Env.Rec()); await env.Chronicle.RecordAsync(Env.Rec()); }
        using (env.Tenants.Use("globex")) { Assert.Equal(1, (await env.Chronicle.RecordAsync(Env.Rec())).Sequence); }

        using (env.Tenants.Use("globex"))
        {
            Assert.Single(await env.Chronicle.QueryAsync());
            await Assert.ThrowsAsync<TenantViolationException>(() => env.Chronicle.QueryAsync(new ChronicleQuery { TenantId = "acme" }));
            await Assert.ThrowsAsync<TenantViolationException>(() => env.Chronicle.RecordAsync(new AuditRecord { Action = "x", TenantId = "acme" }));
        }
        await Assert.ThrowsAsync<TenantContextMissingException>(() => env.Chronicle.RecordAsync(Env.Rec()));
    }

    [Fact]
    public async Task System_context_writes_to_the_system_chain_or_an_explicit_tenant_chain()
    {
        await using var env = new Env();
        using (env.Tenants.UseSystem())
        {
            var sys = await env.Chronicle.RecordAsync(Env.Rec("ops.maintenance"));
            var forAcme = await env.Chronicle.RecordAsync(new AuditRecord { Action = "admin.impersonated", TenantId = "acme" });
            Assert.Equal(ChronicleConstants.SystemChain, sys.Chain);
            Assert.Equal("acme", forAcme.Chain);
            Assert.True((await env.Chronicle.VerifyAsync()).IsValid);
            Assert.True((await env.Chronicle.VerifyAsync("acme")).IsValid);
        }
        using (env.Tenants.Use("acme")) Assert.Equal(["admin.impersonated"], (await env.Chronicle.QueryAsync()).Select(e => e.Action));
    }

    [Fact]
    public async Task Modified_entries_removed_entries_and_forged_chains_are_detected()
    {
        // 1) content edited in storage
        await using (var env = new Env())
        {
            using var _ = env.Tenants.Use("acme");
            for (var i = 0; i < 4; i++) await env.Chronicle.RecordAsync(Env.Rec(entityId: "o" + i));
            ((InMemoryChronicleStore)env.Store).Tamper("acme", 2, e => e with { DataJson = """{"status":"refunded"}""" });
            var v = await env.Chronicle.VerifyAsync();
            Assert.False(v.IsValid);
            Assert.Equal(2, v.FirstBrokenSequence);
            Assert.Contains("modified", v.Reason);
        }
        // 2) entry deleted from the middle
        await using (var env = new Env())
        {
            using var _ = env.Tenants.Use("acme");
            for (var i = 0; i < 4; i++) await env.Chronicle.RecordAsync(Env.Rec());
            ((InMemoryChronicleStore)env.Store).Remove("acme", 3);
            var v = await env.Chronicle.VerifyAsync();
            Assert.False(v.IsValid);
            Assert.Equal(3, v.FirstBrokenSequence);
        }
        // 3) attacker edits an entry AND recomputes the whole hash chain, but cannot produce seals
        await using (var env = new Env())
        {
            using var _ = env.Tenants.Use("acme");
            for (var i = 0; i < 3; i++) await env.Chronicle.RecordAsync(Env.Rec());
            var store = (InMemoryChronicleStore)env.Store;
            byte[] prev = new byte[32];
            for (long seq = 1; seq <= 3; seq++)
            {
                store.Tamper("acme", seq, e =>
                {
                    var forged = e with { DataJson = seq == 2 ? """{"status":"forged"}""" : e.DataJson, PrevHash = prev };
                    return forged with { Hash = EntryHasher.Chain(prev, EntryHasher.Canonical(forged)) };
                });
                prev = (await store.GetAsync("acme", seq, default))!.Hash;
            }
            var v = await env.Chronicle.VerifyAsync();
            Assert.False(v.IsValid);
            Assert.Contains("Seal", v.Reason);
        }
    }

    [Fact]
    public async Task Revoking_the_seal_key_makes_verification_fail()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        await env.Chronicle.RecordAsync(Env.Rec());
        await env.Keys.RevokeAsync("chronicle-seal", 1);
        Assert.False((await env.Chronicle.VerifyAsync()).IsValid);
    }

    [Fact]
    public async Task Pii_is_encrypted_per_field_and_can_be_revealed()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var e = await env.Chronicle.RecordAsync(Env.Rec("user.updated", pii: new() { ["email"] = "ada@example.com", ["name"] = "Ada Lovelace" }, subject: "u1"));

        Assert.Equal(["email", "name"], e.Pii.Keys.Order());
        Assert.DoesNotContain("ada@example.com", Encoding.UTF8.GetString(e.Pii["email"].Envelope));
        Assert.DoesNotContain("ada@example.com", e.DataJson);
        var revealed = await env.Chronicle.RevealAsync(e);
        Assert.Equal(new[] { ("email", "ada@example.com"), ("name", "Ada Lovelace") }, revealed.Select(r => (r.Name, r.Value)));
        Assert.All(revealed, r => Assert.False(r.Shredded));
    }

    [Fact]
    public async Task Pii_without_a_subject_is_rejected_and_ciphertext_cannot_be_moved_between_fields()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        await Assert.ThrowsAsync<ArgumentException>(() => env.Chronicle.RecordAsync(Env.Rec(pii: new() { ["email"] = "x" })));

        var e = await env.Chronicle.RecordAsync(Env.Rec(pii: new() { ["email"] = "a@x.io", ["name"] = "A" }, subject: "u1"));
        var swapped = e with { Pii = new Dictionary<string, EncryptedField> { ["email"] = e.Pii["name"], ["name"] = e.Pii["email"] } };
        await Assert.ThrowsAsync<CipherDecryptionException>(() => env.Chronicle.RevealAsync(swapped)); // AAD binds field name
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task Crypto_shredding_destroys_only_that_subjects_pii_and_keeps_the_chain_valid(bool ef)
    {
        await using var env = new Env(ef);
        using var _ = env.Tenants.Use("acme");
        var ada = await env.Chronicle.RecordAsync(Env.Rec("user.created", data: new JsonObject { ["plan"] = "pro" }, pii: new() { ["email"] = "ada@x.io" }, subject: "ada"));
        var bob = await env.Chronicle.RecordAsync(Env.Rec("user.created", pii: new() { ["email"] = "bob@x.io" }, subject: "bob"));

        await env.Chronicle.ShredSubjectAsync("ada");

        var adaAfter = await env.Chronicle.RevealAsync(ada);
        Assert.Equal([new RevealedField("email", null, true)], adaAfter);       // gone for good
        Assert.Equal("bob@x.io", (await env.Chronicle.RevealAsync(bob)).Single().Value); // others untouched

        var stored = (await env.Chronicle.QueryAsync(new ChronicleQuery { Action = "user.created" })).First(x => x.SubjectId == "ada");
        Assert.Contains("pro", stored.DataJson);                                 // non-PII history survives
        Assert.True((await env.Chronicle.VerifyAsync()).IsValid);                // ciphertext still there ⇒ hashes still match

        var marker = (await env.Chronicle.QueryAsync(new ChronicleQuery { Action = "chronicle.subject-shredded" })).Single();
        Assert.Equal("ada", marker.EntityId);
        Assert.Empty(marker.Pii);
    }

    [Fact]
    public async Task A_shredded_subject_can_be_recorded_again_under_a_fresh_key_without_resurrecting_old_data()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var old = await env.Chronicle.RecordAsync(Env.Rec(pii: new() { ["email"] = "old@x.io" }, subject: "ada"));
        await env.Chronicle.ShredSubjectAsync("ada");
        var fresh = await env.Chronicle.RecordAsync(Env.Rec(pii: new() { ["email"] = "new@x.io" }, subject: "ada"));

        Assert.Null((await env.Chronicle.RevealAsync(old)).Single().Value);
        Assert.Equal("new@x.io", (await env.Chronicle.RevealAsync(fresh)).Single().Value);
    }

    [Fact]
    public async Task Query_filters_paginate_newest_first_and_are_clamped()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        for (var i = 1; i <= 5; i++) { env.Time.Now = env.Time.Now.AddMinutes(1); await env.Chronicle.RecordAsync(Env.Rec(i % 2 == 0 ? "a.even" : "a.odd", entityId: "e" + i)); }

        Assert.Equal([5L, 4, 3, 2, 1], (await env.Chronicle.QueryAsync()).Select(e => e.Sequence));
        Assert.Equal([3L, 2], (await env.Chronicle.QueryAsync(new ChronicleQuery { Skip = 2, Take = 2 })).Select(e => e.Sequence));
        Assert.Equal([4L, 2], (await env.Chronicle.QueryAsync(new ChronicleQuery { Action = "a.even" })).Select(e => e.Sequence));
        Assert.Equal(["e3"], (await env.Chronicle.QueryAsync(new ChronicleQuery { EntityId = "e3" })).Select(e => e.EntityId));
        Assert.Equal([4L, 3, 2], (await env.Chronicle.QueryAsync(new ChronicleQuery { From = env.Time.Now.AddMinutes(-3), To = env.Time.Now.AddMinutes(-1) })).Select(e => e.Sequence)); // inclusive bounds
        Assert.Equal(5, (await env.Chronicle.QueryAsync(new ChronicleQuery { Take = 100000 })).Count);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task Archiving_flags_and_exports_but_never_deletes_and_verification_still_passes(bool ef)
    {
        await using var env = new Env(ef, o => o.OnlineRetention = TimeSpan.FromDays(30));
        using var _ = env.Tenants.Use("acme");
        await env.Chronicle.RecordAsync(Env.Rec());
        await env.Chronicle.RecordAsync(Env.Rec());
        env.Time.Now = env.Time.Now.AddDays(40);
        await env.Chronicle.RecordAsync(Env.Rec());

        var archived = await env.Chronicle.ArchiveExpiredAsync();

        Assert.Equal(2, archived);
        Assert.Equal([3L], (await env.Chronicle.QueryAsync()).Select(e => e.Sequence));                                 // hot view
        var all = await env.Chronicle.QueryAsync(new ChronicleQuery { IncludeArchived = true });
        Assert.Equal(3, all.Count);                                                                                      // nothing deleted
        Assert.Equal([true, true, false], all.OrderBy(e => e.Sequence).Select(e => e.Archived));
        Assert.All(all.Where(e => e.Archived), e => Assert.NotNull(e.ArchiveRef));
        Assert.Equal(2, env.Sink.Written.Sum(w => w.Entries.Count));
        Assert.True((await env.Chronicle.VerifyAsync()).IsValid);                                                        // archived entries still anchor the chain
        Assert.Equal(0, await env.Chronicle.ArchiveExpiredAsync());                                                      // idempotent
    }

    [Fact]
    public async Task Auto_archive_is_disabled_without_a_retention_setting()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        await env.Chronicle.RecordAsync(Env.Rec());
        env.Time.Now = env.Time.Now.AddYears(5);
        Assert.Equal(0, await env.Chronicle.ArchiveExpiredAsync());
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task Concurrent_writers_get_unique_consecutive_sequences_and_a_valid_chain(bool ef)
    {
        await using var env = new Env(ef, o => o.MaxAppendAttempts = 200);
        var tasks = Enumerable.Range(0, 16).Select(i => Task.Run(async () =>
        {
            using var _ = env.Tenants.Use("acme");
            return (await env.Chronicle.RecordAsync(Env.Rec(entityId: "o" + i))).Sequence;
        }));
        var seqs = (await Task.WhenAll(tasks)).Order().ToList();

        Assert.Equal(Enumerable.Range(1, 16).Select(i => (long)i), seqs);
        using var __ = env.Tenants.Use("acme");
        Assert.True((await env.Chronicle.VerifyAsync()).IsValid);
    }

    [Fact]
    public async Task Ef_store_refuses_updates_and_deletes_at_the_application_layer()
    {
        await using var env = new Env(ef: true);
        using var _ = env.Tenants.Use("acme");
        await env.Chronicle.RecordAsync(Env.Rec());
        var dbf = env.Sp.GetRequiredService<IChronicleDbFactory>();

        await using (var db = dbf.CreateTenant())
        {
            var row = await db.Entries.SingleAsync();
            row.DataJson = """{"status":"forged"}""";
            await Assert.ThrowsAsync<ChronicleImmutableException>(() => db.SaveChangesAsync());
        }
        await using (var db = dbf.CreateTenant())
        {
            db.Entries.Remove(await db.Entries.SingleAsync());
            await Assert.ThrowsAsync<ChronicleImmutableException>(() => db.SaveChangesAsync());
        }
        await using (var db = dbf.CreateTenant())
        {
            var row = await db.Entries.SingleAsync();
            row.Archived = true; row.ArchiveRef = "x";
            await db.SaveChangesAsync(); // the archive flag is the one allowed change
        }
    }

    [Fact]
    public void Schema_script_is_rls_protected_and_append_only()
    {
        var options = new DbContextOptionsBuilder<ChronicleDb>().UseNpgsql("Host=localhost;Database=x").Options;
        using var db = new ChronicleDb(options, new FixedTenantContext("t"));
        var script = db.GenerateSchemaScript();
        Assert.Contains("chronicle_entries", script);
        Assert.Contains("FORCE ROW LEVEL SECURITY", script);
        Assert.Contains("BEFORE UPDATE OR DELETE ON chronicle_entries", script);
        Assert.Contains("append-only", script);
    }
}
