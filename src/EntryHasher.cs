using System.Text;

namespace Chronicle;

/// <summary>Deterministic canonical encoding of an entry's content; the hash chain is SHA-256(prevHash ‖ canonical). It covers ciphertext, never plaintext PII, so shredding cannot break verification.</summary>
internal static class EntryHasher
{
    public static byte[] Canonical(AuditEntry e)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.UTF8);
        w.Write((byte)1); // canonical format version
        Str(w, e.Chain);
        w.Write(e.Sequence);
        w.Write(e.Id.ToByteArray());
        w.Write(e.OccurredAt.UtcTicks);
        Str(w, e.Action); Str(w, e.EntityType); Str(w, e.EntityId); Str(w, e.Actor); Str(w, e.SubjectId);
        Str(w, e.DataJson);
        w.Write(e.Pii.Count);
        foreach (var (name, field) in e.Pii.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            Str(w, name);
            w.Write(field.Envelope.Length);
            w.Write(field.Envelope);
        }
        w.Flush();
        return ms.ToArray();
    }

    public static byte[] Chain(byte[] prev, byte[] canonical)
        => System.Security.Cryptography.SHA256.HashData([.. prev, .. canonical]);

    private static void Str(BinaryWriter w, string? s)
    {
        if (s is null) { w.Write(-1); return; }
        var b = Encoding.UTF8.GetBytes(s);
        w.Write(b.Length);
        w.Write(b);
    }
}
