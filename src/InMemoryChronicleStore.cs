namespace Chronicle;

public sealed class InMemoryChronicleStore : IChronicleStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, SortedList<long, AuditEntry>> _chains = new(StringComparer.Ordinal);

    public Task<ChainHead?> GetHeadAsync(string chain, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_chains.TryGetValue(chain, out var list) || list.Count == 0) return Task.FromResult<ChainHead?>(null);
            var last = list.Values[^1];
            return Task.FromResult<ChainHead?>(new ChainHead(last.Sequence, last.Hash));
        }
    }

    public Task<bool> TryAppendAsync(AuditEntry entry, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_chains.TryGetValue(entry.Chain, out var list)) _chains[entry.Chain] = list = [];
            if (list.ContainsKey(entry.Sequence)) return Task.FromResult(false);
            list.Add(entry.Sequence, entry);
            return Task.FromResult(true);
        }
    }

    public Task<IReadOnlyList<AuditEntry>> ReadChainAsync(string chain, long fromSequence, int take, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<AuditEntry>>(_chains.TryGetValue(chain, out var l) ? [.. l.Values.Where(e => e.Sequence >= fromSequence).Take(take)] : []);
    }

    public Task<AuditEntry?> GetAsync(string chain, long sequence, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_chains.TryGetValue(chain, out var l) && l.TryGetValue(sequence, out var e) ? e : null);
    }

    public Task<IReadOnlyList<AuditEntry>> QueryAsync(string chain, ChronicleQuery q, CancellationToken ct)
    {
        lock (_gate)
        {
            IEnumerable<AuditEntry> src = _chains.TryGetValue(chain, out var l) ? l.Values : [];
            src = src.Where(e => (q.IncludeArchived || !e.Archived)
                && (q.EntityType is null || e.EntityType == q.EntityType) && (q.EntityId is null || e.EntityId == q.EntityId)
                && (q.Actor is null || e.Actor == q.Actor) && (q.Action is null || e.Action == q.Action)
                && (q.SubjectId is null || e.SubjectId == q.SubjectId)
                && (q.From is null || e.OccurredAt >= q.From) && (q.To is null || e.OccurredAt <= q.To));
            return Task.FromResult<IReadOnlyList<AuditEntry>>([.. src.OrderByDescending(e => e.Sequence).Skip(q.Skip).Take(q.Take)]);
        }
    }

    public Task<IReadOnlyList<AuditEntry>> GetUnarchivedBeforeAsync(string chain, DateTimeOffset cutoff, int take, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<AuditEntry>>(_chains.TryGetValue(chain, out var l) ? [.. l.Values.Where(e => !e.Archived && e.OccurredAt < cutoff).Take(take)] : []);
    }

    public Task MarkArchivedAsync(string chain, IReadOnlyCollection<long> sequences, string archiveRef, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_chains.TryGetValue(chain, out var l))
                foreach (var s in sequences)
                    if (l.TryGetValue(s, out var e)) l[s] = e with { Archived = true, ArchiveRef = archiveRef }; // only the archive flag ever changes
        }
        return Task.CompletedTask;
    }

    /// <summary>Test hook: simulates an attacker editing storage directly.</summary>
    internal void Tamper(string chain, long sequence, Func<AuditEntry, AuditEntry> edit)
    {
        lock (_gate) _chains[chain][sequence] = edit(_chains[chain][sequence]);
    }

    internal void Remove(string chain, long sequence)
    {
        lock (_gate) _chains[chain].Remove(sequence);
    }
}
