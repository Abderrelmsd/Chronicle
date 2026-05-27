namespace Chronicle;

/// <summary>Tamper-evident audit/history. Acts on the ambient Bedrock tenant (or, in system context, the system chain / an explicit tenant).</summary>
public interface IChronicle
{
    /// <summary>Appends an entry to the chain: sequence + previous hash + HMAC seal, PII encrypted per subject.</summary>
    Task<AuditEntry> RecordAsync(AuditRecord record, CancellationToken cancellationToken = default);

    /// <summary>Newest first. Archived entries are excluded unless <see cref="ChronicleQuery.IncludeArchived"/>.</summary>
    Task<IReadOnlyList<AuditEntry>> QueryAsync(ChronicleQuery? query = null, CancellationToken cancellationToken = default);

    /// <summary>Decrypts an entry's PII fields; fields of shredded subjects come back with <c>Value = null</c>.</summary>
    Task<IReadOnlyList<RevealedField>> RevealAsync(AuditEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Re-computes every hash link and seal in the chain (archived entries included).</summary>
    Task<ChainVerification> VerifyAsync(string? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Crypto-shredding: destroys the subject's PII key so every encrypted PII field about them becomes permanently unreadable,
    /// while non-PII data and chain integrity are untouched. Records a <c>chronicle.subject-shredded</c> entry (no PII).
    /// </summary>
    Task ShredSubjectAsync(string subjectId, string? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>Archives (never deletes) entries older than <paramref name="olderThan"/>: exports to <see cref="IArchiveSink"/>, then flags them archived. Returns the count.</summary>
    Task<int> ArchiveAsync(DateTimeOffset olderThan, string? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>Archives by <see cref="ChronicleOptions.OnlineRetention"/> (for scheduled jobs).</summary>
    Task<int> ArchiveExpiredAsync(string? tenantId = null, CancellationToken cancellationToken = default);
}

/// <summary>Cold-storage export target for archived entries (e.g. an immutable Silo bucket). The default is a no-op: archived entries then simply stay in the store, flagged.</summary>
public interface IArchiveSink
{
    /// <summary>Must be durable before returning; only then are entries flagged archived.</summary>
    Task WriteAsync(string archiveRef, IReadOnlyList<AuditEntry> entries, CancellationToken cancellationToken = default);
}

internal sealed class NullArchiveSink : IArchiveSink
{
    public Task WriteAsync(string archiveRef, IReadOnlyList<AuditEntry> entries, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>Persistence abstraction (Postgres via <c>EfChronicleStore</c>; in-memory for tests). Entries are append-only; only the archive flag may change.</summary>
public interface IChronicleStore
{
    Task<ChainHead?> GetHeadAsync(string chain, CancellationToken ct);

    /// <summary>Appends if (chain, sequence) is free; false when another writer got there first.</summary>
    Task<bool> TryAppendAsync(AuditEntry entry, CancellationToken ct);

    /// <summary>Entries with sequence ≥ <paramref name="fromSequence"/>, ascending, archived included.</summary>
    Task<IReadOnlyList<AuditEntry>> ReadChainAsync(string chain, long fromSequence, int take, CancellationToken ct);

    Task<AuditEntry?> GetAsync(string chain, long sequence, CancellationToken ct);
    Task<IReadOnlyList<AuditEntry>> QueryAsync(string chain, ChronicleQuery query, CancellationToken ct);
    Task<IReadOnlyList<AuditEntry>> GetUnarchivedBeforeAsync(string chain, DateTimeOffset cutoff, int take, CancellationToken ct);
    Task MarkArchivedAsync(string chain, IReadOnlyCollection<long> sequences, string archiveRef, CancellationToken ct);
}
