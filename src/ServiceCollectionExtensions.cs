using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Bedrock;
using Chronicle.Data;

namespace Chronicle;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers <see cref="IChronicle"/>. Requires Cipher and Bedrock's tenant context. Uses the in-memory store unless an <see cref="IChronicleStore"/> is registered (see <see cref="AddChronicleBedrockData"/>).</summary>
    public static IServiceCollection AddChronicle(this IServiceCollection services, Action<ChronicleOptions>? configure = null)
    {
        var o = services.AddOptions<ChronicleOptions>();
        if (configure is not null) o.Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IArchiveSink, NullArchiveSink>();
        services.TryAddSingleton<IChronicleStore, InMemoryChronicleStore>();
        services.TryAddSingleton<ChronicleService>();
        services.TryAddSingleton<IChronicle>(sp => sp.GetRequiredService<ChronicleService>());
        services.TryAddSingleton<IChronicleOutbox, ChronicleOutbox>();
        services.TryAddSingleton<IChronicleIngestor, ChronicleIngestor>();
        return services;
    }

    /// <summary>
    /// Postgres storage through Bedrock sessions: each tenant chain is written on the tenant's own cluster in a transaction (works in Bedrock's
    /// transaction scope). Call <em>before</em> <see cref="AddChronicle"/>.
    /// </summary>
    public static IServiceCollection AddChronicleBedrockSessions(this IServiceCollection services)
    {
        services.AddBedrockSessions<ChronicleDb>(o => o.Configure = (_, _, options) => options.AddInterceptors(new ChronicleImmutabilityInterceptor()));
        services.AddBedrockDbContext<ChronicleDb>(o => o.AddInterceptors(new ChronicleImmutabilityInterceptor())); // the system chain
        services.TryAddSingleton<IChronicleUnits, SessionUnits>();
        services.RemoveAll<IChronicleStore>();
        services.AddSingleton<IChronicleStore, EfChronicleStore>();
        return services;
    }

    /// <summary>Links pending records into their chains in the background (<see cref="IChronicleIngestor"/>), one ingester per cluster at a time.</summary>
    public static IServiceCollection AddChronicleIngestor(this IServiceCollection services) => services.AddHostedService<ChronicleIngestorService>();

    /// <summary>Postgres storage through Bedrock: append-only table, RLS, tenant + system chains. Call <em>before</em> <see cref="AddChronicle"/>.</summary>
    public static IServiceCollection AddChronicleBedrockData(this IServiceCollection services)
    {
        services.AddBedrockDbContext<ChronicleDb>(o => o.AddInterceptors(new ChronicleImmutabilityInterceptor())); // system contexts rely on the DB trigger
        services.TryAddSingleton<IChronicleDbFactory, BedrockChronicleDbFactory>();
        services.TryAddSingleton<IChronicleUnits, FactoryUnits>();
        services.RemoveAll<IChronicleStore>();
        services.AddSingleton<IChronicleStore, EfChronicleStore>();
        return services;
    }
}
