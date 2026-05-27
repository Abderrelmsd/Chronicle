using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using Bedrock;
using Cipher;
using Cipher.Encryption;
using Cipher.Keys;
using Cipher.Signing;

namespace Chronicle;

internal sealed class ChronicleService(IChronicleStore store, IEncryptionService encryption, IHmacService hmac, IKeyStore keys, IArchiveSink archive,
    ITenantContext tenant, IOptions<ChronicleOptions> options, TimeProvider time) : IChronicle
{
    private readonly ChronicleOptions _o = options.Value;
    private static readonly byte[] Genesis = new byte[32];

    // ---- write ---------------------------------------------------------------------------------------------

    public async Task<AuditEntry> RecordAsync(AuditRecord record, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(record.Action)) throw new ArgumentException("Action is required.", nameof(record));
        var chain = ResolveChain(record.TenantId);
        var pii = record.Pii ?? new Dictionary<string, string>();
        if (pii.Count > 0 && string.IsNullOrWhiteSpace(record.SubjectId)) throw new ArgumentException("PII requires a SubjectId (whose key encrypts it).", nameof(record));

        await EnsureKey(_o.SealKeyId, ct);
        var id = Guid.NewGuid();
        var encrypted = await EncryptPii(chain, record.SubjectId, id, pii, ct);
        var dataJson = (record.Data ?? new JsonObject()).ToJsonString();

        for (var attempt = 0; attempt < _o.MaxAppendAttempts; attempt++)
        {
            var head = await store.GetHeadAsync(chain, ct);
            var prev = head?.Hash ?? Genesis;
            var unsealed = new AuditEntry(id, chain, (head?.Sequence ?? 0) + 1, record.OccurredAt ?? time.GetUtcNow(), record.Action, record.EntityType, record.EntityId,
                record.Actor, record.SubjectId, dataJson, encrypted, prev, [], 0, []);
            var hash = EntryHasher.Chain(prev, EntryHasher.Canonical(unsealed));
            var seal = await hmac.SignAsync(_o.SealKeyId, hash, ct);
            var entry = unsealed with { Hash = hash, Seal = seal.Value, SealKeyVersion = seal.KeyVersion };
            if (await store.TryAppendAsync(entry, ct)) return entry;
        }
        throw new ChronicleConflictException();
    }

    private async Task<Dictionary<string, EncryptedField>> EncryptPii(string chain, string? subjectId, Guid entryId, IReadOnlyDictionary<string, string> pii, CancellationToken ct)
    {
        var result = new Dictionary<string, EncryptedField>(StringComparer.Ordinal);
        if (pii.Count == 0) return result;
        var keyId = SubjectKeyId(chain, subjectId!);
        await EnsureKey(keyId, ct);
        foreach (var (name, value) in pii)
            result[name] = new EncryptedField(await encryption.EncryptAsync(keyId, Encoding.UTF8.GetBytes(value), Aad(chain, entryId, name), ct));
        return result;
    }

    // ---- read ----------------------------------------------------------------------------------------------

    public Task<IReadOnlyList<AuditEntry>> QueryAsync(ChronicleQuery? query = null, CancellationToken ct = default)
    {
        query ??= new ChronicleQuery();
        return store.QueryAsync(ResolveChain(query.TenantId), query with { Take = Math.Clamp(query.Take, 1, 1000) }, ct);
    }

    public async Task<IReadOnlyList<RevealedField>> RevealAsync(AuditEntry entry, CancellationToken ct = default)
    {
        EnsureChainAccess(entry.Chain);
        var result = new List<RevealedField>();
        foreach (var (name, field) in entry.Pii.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            try
            {
                var keyId = SubjectKeyId(entry.Chain, entry.SubjectId!);
                var plain = await encryption.DecryptAsync(keyId, field.Envelope, Aad(entry.Chain, entry.Id, name), ct);
                result.Add(new RevealedField(name, Encoding.UTF8.GetString(plain), false));
            }
            catch (Exception ex) when (ex is CipherKeyRevokedException or CipherKeyNotFoundException)
            {
                result.Add(new RevealedField(name, null, true)); // shredded
            }
        }
        return result;
    }

    // ---- integrity -----------------------------------------------------------------------------------------

    public async Task<ChainVerification> VerifyAsync(string? tenantId = null, CancellationToken ct = default)
    {
        var chain = ResolveChain(tenantId);
        var prevHash = Genesis;
        long expected = 1, checkedCount = 0;

        while (true)
        {
            var page = await store.ReadChainAsync(chain, expected, _o.VerificationPageSize, ct);
            if (page.Count == 0) break;
            foreach (var e in page)
            {
                if (e.Sequence != expected) return new(false, checkedCount, expected, $"Sequence gap: expected {expected}, found {e.Sequence} (an entry was removed).");
                if (e.Chain != chain) return new(false, checkedCount, e.Sequence, "Entry belongs to a different chain.");
                if (!CryptographicOperations.FixedTimeEquals(e.PrevHash, prevHash)) return new(false, checkedCount, e.Sequence, "Previous-hash link is broken.");
                var recomputed = EntryHasher.Chain(e.PrevHash, EntryHasher.Canonical(e));
                if (!CryptographicOperations.FixedTimeEquals(recomputed, e.Hash)) return new(false, checkedCount, e.Sequence, "Entry content does not match its hash (modified).");
                if (!await SealValid(e, ct)) return new(false, checkedCount, e.Sequence, "Seal is invalid (chain was re-computed without the seal key, or the seal key was revoked).");
                prevHash = e.Hash; expected++; checkedCount++;
            }
        }
        return new(true, checkedCount);
    }

    private async Task<bool> SealValid(AuditEntry e, CancellationToken ct)
    {
        try { return await hmac.VerifyAsync(_o.SealKeyId, e.SealKeyVersion, e.Hash, e.Seal, ct); }
        catch (CipherException) { return false; }
    }

    // ---- shredding & archiving -----------------------------------------------------------------------------

    public async Task ShredSubjectAsync(string subjectId, string? tenantId = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId)) throw new ArgumentException("Subject id is required.", nameof(subjectId));
        var chain = ResolveChain(tenantId);
        var keyId = SubjectKeyId(chain, subjectId);

        for (var v = 1; ; v++) // revoke every version of the subject's key
        {
            try { await keys.RevokeAsync(keyId, v, ct); }
            catch (CipherKeyNotFoundException) { break; }
        }
        await RecordAsync(new AuditRecord
        {
            Action = "chronicle.subject-shredded", EntityType = "subject", EntityId = subjectId, TenantId = tenantId,
            Data = new JsonObject { ["subjectId"] = subjectId }, // an opaque id, not PII by itself
        }, ct);
    }

    public async Task<int> ArchiveAsync(DateTimeOffset olderThan, string? tenantId = null, CancellationToken ct = default)
    {
        var chain = ResolveChain(tenantId);
        var total = 0;
        while (true)
        {
            var batch = await store.GetUnarchivedBeforeAsync(chain, olderThan, 500, ct);
            if (batch.Count == 0) return total;
            var archiveRef = $"{chain}/{time.GetUtcNow():yyyyMMddTHHmmssfff}-{batch[0].Sequence}-{batch[^1].Sequence}";
            await archive.WriteAsync(archiveRef, batch, ct); // durable first; only then flag
            await store.MarkArchivedAsync(chain, [.. batch.Select(b => b.Sequence)], archiveRef, ct);
            total += batch.Count;
        }
    }

    public Task<int> ArchiveExpiredAsync(string? tenantId = null, CancellationToken ct = default)
        => _o.OnlineRetention is { } r ? ArchiveAsync(time.GetUtcNow() - r, tenantId, ct) : Task.FromResult(0);

    // ---- helpers -------------------------------------------------------------------------------------------

    private string ResolveChain(string? requested)
    {
        if (tenant.TenantId is { } t)
        {
            if (requested is not null && requested != t) throw new TenantViolationException("Cannot access another tenant's chronicle from a tenant context.");
            return t;
        }
        if (tenant.IsSystem) return requested ?? ChronicleConstants.SystemChain;
        throw new TenantContextMissingException();
    }

    private void EnsureChainAccess(string chain)
    {
        if (tenant.IsSystem) return;
        if (tenant.TenantId != chain) throw new TenantViolationException("That entry belongs to another chain.");
    }

    private string SubjectKeyId(string chain, string subjectId) => $"{_o.PiiKeyPrefix}.{chain}.{subjectId}";
    private static byte[] Aad(string chain, Guid entryId, string field) => Encoding.UTF8.GetBytes($"chronicle|{chain}|{entryId}|{field}");

    private async Task EnsureKey(string keyId, CancellationToken ct)
    {
        try { await keys.GetActiveAsync(keyId, ct); }
        catch (CipherKeyNotFoundException) { await keys.RotateAsync(keyId, KeyKind.Symmetric, ct); }
    }
}
