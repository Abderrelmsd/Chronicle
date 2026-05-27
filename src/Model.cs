using System.Text.Json.Nodes;

namespace Chronicle;

public static class ChronicleConstants
{
    /// <summary>Chain for cross-tenant/system events. Not a valid tenant id (Passport tenant ids can't contain '~').</summary>
    public const string SystemChain = "~system";
}

/// <summary>A PII field encrypted under its data subject's key (AES-GCM via Cipher). Destroying the key shreds the field; the ciphertext stays, so the chain still verifies.</summary>
public sealed record EncryptedField(byte[] Envelope);

/// <summary>An immutable, hash-chained history entry.</summary>
public sealed record AuditEntry(
    Guid Id,
    string Chain,
    long Sequence,
    DateTimeOffset OccurredAt,
    string Action,
    string? EntityType,
    string? EntityId,
    string? Actor,
    string? SubjectId,
    string DataJson,
    IReadOnlyDictionary<string, EncryptedField> Pii,
    byte[] PrevHash,
    byte[] Hash,
    int SealKeyVersion,
    byte[] Seal,
    bool Archived = false,
    string? ArchiveRef = null);

/// <summary>What callers record. <see cref="Data"/> is plaintext (must contain no PII); <see cref="Pii"/> fields are encrypted per <see cref="SubjectId"/>.</summary>
public sealed class AuditRecord
{
    public required string Action { get; init; }
    public string? EntityType { get; init; }
    public string? EntityId { get; init; }
    public string? Actor { get; init; }
    public JsonObject? Data { get; init; }
    /// <summary>Personal data (name → value), encrypted field-by-field under the subject's key. Requires <see cref="SubjectId"/>.</summary>
    public IReadOnlyDictionary<string, string>? Pii { get; init; }
    /// <summary>The data subject the PII belongs to (a principal/customer id).</summary>
    public string? SubjectId { get; init; }
    /// <summary>System contexts only: which tenant's chain to write to (default: the system chain).</summary>
    public string? TenantId { get; init; }
    public DateTimeOffset? OccurredAt { get; init; }
}

public sealed record ChronicleQuery
{
    public string? EntityType { get; init; }
    public string? EntityId { get; init; }
    public string? Actor { get; init; }
    public string? Action { get; init; }
    public string? SubjectId { get; init; }
    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }
    public bool IncludeArchived { get; init; }
    public int Skip { get; init; }
    public int Take { get; init; } = 100;
    /// <summary>System contexts only: query this chain instead of the system chain.</summary>
    public string? TenantId { get; init; }
}

public sealed record ChainHead(long Sequence, byte[] Hash);

public sealed record ChainVerification(bool IsValid, long EntriesChecked, long? FirstBrokenSequence = null, string? Reason = null);

/// <summary>PII of one entry after decryption. <c>Value</c> is null when the subject has been shredded.</summary>
public sealed record RevealedField(string Name, string? Value, bool Shredded);

public class ChronicleException(string message) : Exception(message);
public sealed class ChronicleImmutableException(string message) : ChronicleException(message);
public sealed class ChronicleConflictException() : ChronicleException("Could not append to the chain after several attempts (heavy contention).");
