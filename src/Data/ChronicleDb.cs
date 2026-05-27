using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Bedrock;

namespace Chronicle.Data;

public class ChronicleEntryRow : ITenantScoped
{
    /// <summary>The chain: a tenant id, or <see cref="ChronicleConstants.SystemChain"/>.</summary>
    public string TenantId { get; set; } = "";
    public long Sequence { get; set; }
    public Guid Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string Action { get; set; } = "";
    public string? EntityType { get; set; }
    public string? EntityId { get; set; }
    public string? Actor { get; set; }
    public string? SubjectId { get; set; }
    public string DataJson { get; set; } = "{}";
    public string PiiJson { get; set; } = "{}";
    public byte[] PrevHash { get; set; } = [];
    public byte[] Hash { get; set; } = [];
    public int SealKeyVersion { get; set; }
    public byte[] Seal { get; set; } = [];
    public bool Archived { get; set; }
    public string? ArchiveRef { get; set; }

    public static ChronicleEntryRow From(AuditEntry e) => new()
    {
        TenantId = e.Chain, Sequence = e.Sequence, Id = e.Id, OccurredAt = e.OccurredAt, Action = e.Action, EntityType = e.EntityType, EntityId = e.EntityId,
        Actor = e.Actor, SubjectId = e.SubjectId, DataJson = e.DataJson,
        PiiJson = JsonSerializer.Serialize(e.Pii.ToDictionary(kv => kv.Key, kv => Convert.ToBase64String(kv.Value.Envelope))),
        PrevHash = e.PrevHash, Hash = e.Hash, SealKeyVersion = e.SealKeyVersion, Seal = e.Seal, Archived = e.Archived, ArchiveRef = e.ArchiveRef,
    };

    public AuditEntry ToEntry() => new(Id, TenantId, Sequence, OccurredAt, Action, EntityType, EntityId, Actor, SubjectId, DataJson,
        (JsonSerializer.Deserialize<Dictionary<string, string>>(PiiJson) ?? []).ToDictionary(kv => kv.Key, kv => new EncryptedField(Convert.FromBase64String(kv.Value))),
        PrevHash, Hash, SealKeyVersion, Seal, Archived, ArchiveRef);
}

public sealed class ChronicleDb(DbContextOptions<ChronicleDb> options, ITenantContext tenant) : BedrockDbContext(options, tenant)
{
    public DbSet<ChronicleEntryRow> Entries => Set<ChronicleEntryRow>();

    protected override void OnModelCreating(ModelBuilder mb)
    {
        mb.Entity<ChronicleEntryRow>(e =>
        {
            e.ToTable("chronicle_entries");
            e.HasKey(x => new { x.TenantId, x.Sequence }); // the primary key is what makes concurrent appends to one chain collide
            e.Property(x => x.Sequence).HasColumnName("sequence");
            e.Property(x => x.Id).HasColumnName("id");
            e.Property(x => x.OccurredAt).HasColumnName("occurred_at");
            e.Property(x => x.Action).HasColumnName("action").HasMaxLength(200);
            e.Property(x => x.EntityType).HasColumnName("entity_type").HasMaxLength(200);
            e.Property(x => x.EntityId).HasColumnName("entity_id").HasMaxLength(200);
            e.Property(x => x.Actor).HasColumnName("actor").HasMaxLength(200);
            e.Property(x => x.SubjectId).HasColumnName("subject_id").HasMaxLength(200);
            e.Property(x => x.DataJson).HasColumnName("data_json");
            e.Property(x => x.PiiJson).HasColumnName("pii_json");
            e.Property(x => x.PrevHash).HasColumnName("prev_hash");
            e.Property(x => x.Hash).HasColumnName("hash");
            e.Property(x => x.SealKeyVersion).HasColumnName("seal_key_version");
            e.Property(x => x.Seal).HasColumnName("seal");
            e.Property(x => x.Archived).HasColumnName("archived");
            e.Property(x => x.ArchiveRef).HasColumnName("archive_ref").HasMaxLength(300);
            e.HasIndex(x => new { x.TenantId, x.EntityType, x.EntityId });
            e.HasIndex(x => new { x.TenantId, x.OccurredAt });
            e.HasIndex(x => new { x.TenantId, x.SubjectId });
            e.HasIndex(x => x.Id).IsUnique();
        });
        base.OnModelCreating(mb);
    }

    /// <summary>DDL + RLS + a trigger that makes the table append-only at the database level (only <c>archived</c>/<c>archive_ref</c> may change; DELETE is forbidden).</summary>
    public string GenerateSchemaScript() => this.GenerateScript() + Environment.NewLine + ImmutabilitySql;

    public const string ImmutabilitySql = """
        CREATE OR REPLACE FUNCTION chronicle_forbid_mutation() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'chronicle_entries is append-only: DELETE is not allowed' USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          IF (NEW.tenant_id, NEW.sequence, NEW.id, NEW.occurred_at, NEW.action, NEW.entity_type, NEW.entity_id, NEW.actor, NEW.subject_id,
              NEW.data_json, NEW.pii_json, NEW.prev_hash, NEW.hash, NEW.seal_key_version, NEW.seal)
             IS DISTINCT FROM
             (OLD.tenant_id, OLD.sequence, OLD.id, OLD.occurred_at, OLD.action, OLD.entity_type, OLD.entity_id, OLD.actor, OLD.subject_id,
              OLD.data_json, OLD.pii_json, OLD.prev_hash, OLD.hash, OLD.seal_key_version, OLD.seal) THEN
            RAISE EXCEPTION 'chronicle_entries is append-only: only archived/archive_ref may change' USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END $$ LANGUAGE plpgsql;
        DROP TRIGGER IF EXISTS chronicle_entries_immutable ON chronicle_entries;
        CREATE TRIGGER chronicle_entries_immutable BEFORE UPDATE OR DELETE ON chronicle_entries
          FOR EACH ROW EXECUTE FUNCTION chronicle_forbid_mutation();
        """;
}

/// <summary>Application-level twin of the DB trigger: refuses deletes and any edit other than the archive flag.</summary>
public sealed class ChronicleImmutabilityInterceptor : SaveChangesInterceptor
{
    private static readonly HashSet<string> Mutable = [nameof(ChronicleEntryRow.Archived), nameof(ChronicleEntryRow.ArchiveRef)];

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result) { Check(eventData.Context); return result; }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        Check(eventData.Context);
        return ValueTask.FromResult(result);
    }

    private static void Check(DbContext? db)
    {
        if (db is null) return;
        foreach (var entry in db.ChangeTracker.Entries<ChronicleEntryRow>())
        {
            if (entry.State == EntityState.Deleted) throw new ChronicleImmutableException("Chronicle entries can never be deleted; archive them instead.");
            if (entry.State == EntityState.Modified && entry.Properties.Any(p => p.IsModified && !Mutable.Contains(p.Metadata.Name)))
                throw new ChronicleImmutableException("Chronicle entries are immutable; only the archive flag may change.");
        }
    }
}
