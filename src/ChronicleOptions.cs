namespace Chronicle;

public sealed class ChronicleOptions
{
    public const string SectionName = "Chronicle";

    /// <summary>Cipher key name used to HMAC-seal every entry hash, so an attacker with database write access still can't forge a valid chain.</summary>
    public string SealKeyId { get; set; } = "chronicle-seal";

    /// <summary>Prefix of per-subject PII key names: <c>{prefix}.{chain}.{subjectId}</c>.</summary>
    public string PiiKeyPrefix { get; set; } = "chronicle.pii";

    /// <summary>Entries older than this are archived (never deleted) by <c>ArchiveExpiredAsync</c>. Null = never auto-archive.</summary>
    public TimeSpan? OnlineRetention { get; set; }

    public int MaxAppendAttempts { get; set; } = 8;
    public int VerificationPageSize { get; set; } = 500;

    /// <summary>The pending table of the transactional outbox (<see cref="IChronicleOutbox"/>), in <see cref="PendingSchema"/>.</summary>
    public string PendingTable { get; set; } = ChroniclePending.DefaultTable;

    public string PendingSchema { get; set; } = "public";

    /// <summary>Pending records linked per cluster in one ingest pass.</summary>
    public int IngestBatchSize { get; set; } = 500;

    /// <summary>How long the background ingester waits when nothing is pending.</summary>
    public TimeSpan IngestInterval { get; set; } = TimeSpan.FromSeconds(1);

    internal string PendingTableSql => $"\"{PendingSchema}\".\"{PendingTable}\"";
}
