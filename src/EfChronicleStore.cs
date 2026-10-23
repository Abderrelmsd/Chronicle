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

/// <summary>A context for one operation on a chain, with how to commit it (a Bedrock session's commit, or nothing for a plain context).</summary>
internal sealed class ChronicleUnit(ChronicleDb db, Func<CancellationToken, Task> commit, IAsyncDisposable owner) : IAsyncDisposable
{
    public ChronicleDb Db { get; } = db;

    public Task CommitAsync(CancellationToken ct) => commit(ct);

    public ValueTask DisposeAsync() => owner.DisposeAsync();
}

internal interface IChronicleUnits
{
    Task<ChronicleUnit> OpenAsync(string chain, CancellationToken ct);
}

/// <summary>Plain contexts from <see cref="IChronicleDbFactory"/> (Bedrock connection scope, or tests): each statement commits by itself.</summary>
internal sealed class FactoryUnits(IChronicleDbFactory dbf) : IChronicleUnits
{
    public Task<ChronicleUnit> OpenAsync(string chain, CancellationToken ct)
    {
        var db = chain == ChronicleConstants.SystemChain ? dbf.CreateSystem() : dbf.CreateTenant();
        return Task.FromResult(new ChronicleUnit(db, _ => Task.CompletedTask, db));
    }
}

/// <summary>
/// Bedrock sessions for tenant chains: a transaction on the tenant's own cluster (so the entries live with the tenant's data, and transaction
/// scope is honoured). The system chain uses a system context on the first cluster.
/// </summary>
internal sealed class SessionUnits(IBedrockSessionFactory<ChronicleDb> sessions, IBedrockDbContextFactory<ChronicleDb> contexts) : IChronicleUnits
{
    public async Task<ChronicleUnit> OpenAsync(string chain, CancellationToken ct)
    {
        if (chain == ChronicleConstants.SystemChain)
        {
            var db = contexts.CreateSystem();
            return new ChronicleUnit(db, _ => Task.CompletedTask, db);
        }

        var session = await sessions.OpenAsync(ct);
        return new ChronicleUnit(session.Db, session.CommitAsync, session);
    }
}

/// <summary>EF Core store: tenant chains on the tenant's connection (RLS-scoped), the system chain on the system connection.</summary>
internal sealed class EfChronicleStore(IChronicleUnits units) : IChronicleStore
{
    public async Task<ChainHead?> GetHeadAsync(string chain, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        var row = await unit.Db.Entries.Where(e => e.TenantId == chain).OrderByDescending(e => e.Sequence).Select(e => new { e.Sequence, e.Hash }).FirstOrDefaultAsync(ct);
        return row is null ? null : new ChainHead(row.Sequence, row.Hash);
    }

    public async Task<bool> TryAppendAsync(AuditEntry entry, CancellationToken ct)
    {
        Exception failure;
        await using (var unit = await units.OpenAsync(entry.Chain, ct))
        {
            unit.Db.Entries.Add(ChronicleEntryRow.From(entry));
            try
            {
                await unit.Db.SaveChangesAsync(ct);
                await unit.CommitAsync(ct);
                return true;
            }
            catch (Exception ex) when (ex is DbUpdateException or InvalidOperationException or ArgumentException)
            {
                failure = ex; // checked below, on a fresh unit: a failed statement leaves a transaction unusable
            }
        }

        // Primary-key collision on (chain, sequence): another writer appended first. Anything else is a real failure.
        await using var check = await units.OpenAsync(entry.Chain, ct);
        if (await check.Db.Entries.IgnoreQueryFilters().AsNoTracking().AnyAsync(e => e.TenantId == entry.Chain && e.Sequence == entry.Sequence, ct)) return false;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        return false;
    }

    public async Task<bool> ContainsAsync(string chain, Guid entryId, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        return await unit.Db.Entries.AsNoTracking().AnyAsync(e => e.TenantId == chain && e.Id == entryId, ct);
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadChainAsync(string chain, long fromSequence, int take, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        var rows = await unit.Db.Entries.AsNoTracking().Where(e => e.TenantId == chain && e.Sequence >= fromSequence).OrderBy(e => e.Sequence).Take(take).ToListAsync(ct);
        return [.. rows.Select(r => r.ToEntry())];
    }

    public async Task<AuditEntry?> GetAsync(string chain, long sequence, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        return (await unit.Db.Entries.AsNoTracking().SingleOrDefaultAsync(e => e.TenantId == chain && e.Sequence == sequence, ct))?.ToEntry();
    }

    public async Task<IReadOnlyList<AuditEntry>> QueryAsync(string chain, ChronicleQuery q, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        var query = unit.Db.Entries.AsNoTracking().Where(e => e.TenantId == chain);
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
        await using var unit = await units.OpenAsync(chain, ct);
        var rows = await unit.Db.Entries.AsNoTracking().Where(e => e.TenantId == chain && !e.Archived && e.OccurredAt < cutoff).OrderBy(e => e.Sequence).Take(take).ToListAsync(ct);
        return [.. rows.Select(r => r.ToEntry())];
    }

    public async Task MarkArchivedAsync(string chain, IReadOnlyCollection<long> sequences, string archiveRef, CancellationToken ct)
    {
        await using var unit = await units.OpenAsync(chain, ct);
        var rows = await unit.Db.Entries.Where(e => e.TenantId == chain && sequences.Contains(e.Sequence)).ToListAsync(ct);
        foreach (var r in rows) { r.Archived = true; r.ArchiveRef = archiveRef; }
        await unit.Db.SaveChangesAsync(ct);
        await unit.CommitAsync(ct);
    }
}
