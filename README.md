# Chronicle

An immutable, tamper-evident audit trail. Chronicle records who did what and when, chains every entry to the one before it, and keeps that history verifiable. It is what makes the hard deletes in Bedrock safe: data can be removed, but the history of what happened cannot be quietly rewritten.

Use it for audit logs, compliance history, and any place you need to prove that records were not altered after the fact.

## Install

```bash
dotnet add package Chronicle
```

## Quick start

```csharp
services.AddChronicleBedrockData();                  // Postgres through Bedrock (optional; an in-memory store is the default)
services.AddChronicle(o => o.OnlineRetention = TimeSpan.FromDays(365));

await chronicle.RecordAsync(new AuditRecord
{
    Action = "user.updated", EntityType = "user", EntityId = id, Actor = adminId,
    Data = new JsonObject { ["plan"] = "pro" },                        // plaintext: keep PII out of here
    Pii  = new Dictionary<string, string> { ["email"] = "ada@x.io" },  // encrypted per field, per subject
    SubjectId = id,
});

var check = await chronicle.VerifyAsync();           // recomputes hash links and HMAC seals
await chronicle.ShredSubjectAsync(id);               // GDPR erasure: destroys that subject's PII key only
await chronicle.ArchiveExpiredAsync();               // retention means archive, never delete
```

## How tamper-evidence works

- **One chain per tenant**, plus a system chain (`~system`) for cross-tenant events. Each entry stores `PrevHash` and `Hash = SHA-256(prevHash || canonical entry)`. The canonical encoding is length-prefixed and versioned.
- **Every hash is sealed with an HMAC** (Cipher key `chronicle-seal`). Someone who edits rows and recomputes the whole chain still cannot forge the seals. Revoking the seal key makes verification fail on purpose.
- **`VerifyAsync`** walks the chain in pages and checks sequence continuity, the link, the hash and the seal. It reports the first broken sequence number and the reason.

## Personal data and erasure

Put personal data in `Pii`, not `Data`. Each PII value is encrypted individually (AES-GCM through Cipher) under a key per subject, `chronicle.pii.{chain}.{subject}`. `ShredSubjectAsync` revokes that key, so the values become unreadable while everything else in the entry stays readable. The hash covers the ciphertext, so the chain still verifies after a shred.

## Retention

Retention **archives**, it never deletes. `ArchiveAsync` first exports entries to an `IArchiveSink` (durable before anything changes), then flags them `Archived` with an `ArchiveRef`. Archived entries stay in the chain and in verification. The archive flags are the only mutable columns.

## Storage

Entries live behind `IChronicleStore`.
- The in-memory store is the default.
- The EF/Postgres store is `ChronicleDb : BedrockDbContext`. The primary key `(chain, sequence)` makes concurrent appends collide, and Chronicle retries. Bedrock RLS applies, and `ChronicleDb.GenerateSchemaScript()` includes a database trigger that forbids `DELETE` and any `UPDATE` except the archive columns; an EF interceptor enforces the same rule in the application.

The chain is chosen from the ambient Bedrock tenant. A tenant context cannot touch other chains; a system context writes to `~system` or names a tenant explicitly.

## Configuration

Section `Chronicle`.

| Option | Default | Meaning |
|---|---|---|
| `SealKeyId` | `chronicle-seal` | Cipher key used to seal entry hashes |
| `PiiKeyPrefix` | `chronicle.pii` | Prefix of the per-subject PII keys |
| `OnlineRetention` | `null` | How long entries stay "online" before `ArchiveExpiredAsync` archives them. `null` means never |
| `MaxAppendAttempts` | `8` | Retries when concurrent appends collide |
| `VerificationPageSize` | `500` | Entries read per page during verification |

## Reacting to other packages

Chronicle does not depend on Mesh. To audit events from other packages (for example Keep's), subscribe in the host with `SubscribeRaw` and call `RecordAsync`.

## Not included yet

External anchoring of chain heads (periodic notarization) and a scheduled verification job. Run `VerifyAsync` from Metronome if you want one.

## Depends on

Bedrock, Cipher.
