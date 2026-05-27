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
        services.TryAddSingleton<IChronicle, ChronicleService>();
        return services;
    }

    /// <summary>Postgres storage through Bedrock: append-only table, RLS, tenant + system chains. Call <em>before</em> <see cref="AddChronicle"/>.</summary>
    public static IServiceCollection AddChronicleBedrockData(this IServiceCollection services)
    {
        services.AddBedrockDbContext<ChronicleDb>(o => o.AddInterceptors(new ChronicleImmutabilityInterceptor())); // system contexts rely on the DB trigger
        services.TryAddSingleton<IChronicleDbFactory, BedrockChronicleDbFactory>();
        services.RemoveAll<IChronicleStore>();
        services.AddSingleton<IChronicleStore, EfChronicleStore>();
        return services;
    }
}
