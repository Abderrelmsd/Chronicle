using Microsoft.EntityFrameworkCore;
using Bedrock;
using Chronicle.Data;

namespace Chronicle;

/// <summary>Creates contexts for Chronicle's tables. Production binds to Bedrock (tenant + system connections).</summary>
public interface IChronicleDbFactory
{
    ChronicleDb CreateTenant();
    ChronicleDb CreateSystem();
}

internal sealed class BedrockChronicleDbFactory(IBedrockDbContextFactory<ChronicleDb> inner) : IChronicleDbFactory
{
    public ChronicleDb CreateTenant() => inner.CreateTenant();
    public ChronicleDb CreateSystem() => inner.CreateSystem();
}

/// <summary>EF Core store: tenant chains use the tenant (RLS-scoped) connection; the system chain uses the system connection.</summary>
internal sealed class EfChronicleStore(IChronicleDbFactory dbf) : IChronicleStore
{
    private ChronicleDb Db(string chain) => chain == ChronicleConstants.SystemChain ? dbf.CreateSystem() : dbf.CreateTenant();

    public async Task<ChainHead?> GetHeadAsync(string chain, CancellationToken ct)
    {
        await using var db = Db(chain);
        var row = await db.Entries.Where(e => e.TenantId == chain).OrderByDescending(e => e.Sequence).Select(e => new { e.Sequence, e.Hash }).FirstOrDefaultAsync(ct);
        return row is null ? null : new ChainHead(row.Sequence, row.Hash);
    }

    public async Task<bool> TryAppendAsync(AuditEntry entry, CancellationToken ct)
    {
        await using var db = Db(entry.Chain);
        db.Entries.Add(ChronicleEntryRow.From(entry));
        try { await db.SaveChangesAsync(ct); return true; }
        catch (Exception ex) when (ex is DbUpdateException or InvalidOperationException or ArgumentException)
        {
            // Primary-key collision on (chain, sequence): another writer appended first. Anything else is a real failure.
            if (await db.Entries.IgnoreQueryFilters().AsNoTracking().AnyAsync(e => e.TenantId == entry.Chain && e.Sequence == entry.Sequence, ct)) return false;
            throw;
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadChainAsync(string chain, long fromSequence, int take, CancellationToken ct)
    {
        await using var db = Db(chain);
        var rows = await db.Entries.AsNoTracking().Where(e => e.TenantId == chain && e.Sequence >= fromSequence).OrderBy(e => e.Sequence).Take(take).ToListAsync(ct);
        return [.. rows.Select(r => r.ToEntry())];
    }

    public async Task<AuditEntry?> GetAsync(string chain, long sequence, CancellationToken ct)
    {
        await using var db = Db(chain);
        return (await db.Entries.AsNoTracking().SingleOrDefaultAsync(e => e.TenantId == chain && e.Sequence == sequence, ct))?.ToEntry();
    }

    public async Task<IReadOnlyList<AuditEntry>> QueryAsync(string chain, ChronicleQuery q, CancellationToken ct)
    {
        await using var db = Db(chain);
        var query = db.Entries.AsNoTracking().Where(e => e.TenantId == chain);
        if (!q.IncludeArchived) query = query.Where(e => !e.Archived);
        if (q.EntityType is not null) query = query.Where(e => e.EntityType == q.EntityType);
        if (q.EntityId is not null) query = query.Where(e => e.EntityId == q.EntityId);
        if (q.Actor is not null) query = query.Where(e => e.Actor == q.Actor);
        if (q.Action is not null) query = query.Where(e => e.Action == q.Action);
        if (q.SubjectId is not null) query = query.Where(e => e.SubjectId == q.SubjectId);
        if (q.From is not null) query = query.Where(e => e.OccurredAt >= q.From);
        if (q.To is not null) query = query.Where(e => e.OccurredAt <= q.To);
        var rows = await query.OrderByDescending(e => e.Sequence).Skip(q.Skip).Take(q.Take).ToListAsync(ct);
        return [.. rows.Select(r => r.ToEntry())];
    }

    public async Task<IReadOnlyList<AuditEntry>> GetUnarchivedBeforeAsync(string chain, DateTimeOffset cutoff, int take, CancellationToken ct)
    {
        await using var db = Db(chain);
        var rows = await db.Entries.AsNoTracking().Where(e => e.TenantId == chain && !e.Archived && e.OccurredAt < cutoff).OrderBy(e => e.Sequence).Take(take).ToListAsync(ct);
        return [.. rows.Select(r => r.ToEntry())];
    }

    public async Task MarkArchivedAsync(string chain, IReadOnlyCollection<long> sequences, string archiveRef, CancellationToken ct)
    {
        await using var db = Db(chain);
        var rows = await db.Entries.Where(e => e.TenantId == chain && sequences.Contains(e.Sequence)).ToListAsync(ct);
        foreach (var r in rows) { r.Archived = true; r.ArchiveRef = archiveRef; }
        await db.SaveChangesAsync(ct);
    }
}
