namespace Api.Identity.DataAccessLayer.Seeders;

using Api.Identity.DataAccessLayer.Context;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

/// <summary>
///     This class is used to initialize the database.
/// </summary>
public sealed class InitializeDb : IHostedService
{
    private readonly IHostEnvironment env;

    private readonly IServiceScopeFactory scopeFactory;

    /// <summary>
    ///     Initializes a new instance of the <see cref="InitializeDb" /> class.
    /// </summary>
    /// <param name="env">Hosting environment info from DI.</param>
    /// <param name="scopeFactory">Database context.</param>
    public InitializeDb(IHostEnvironment env, IServiceScopeFactory scopeFactory)
    {
        this.env = env;
        this.scopeFactory = scopeFactory;
    }

    /// <summary>
    ///     Gets called when webHost is being started and before pipeline is initiated.
    /// </summary>
    /// <param name="cancellationToken">token use to control async task cancellation.</param>
    /// <returns>Task completion status.</returns>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = this.scopeFactory.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        await context.Database.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
        await context.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        var userSeeder = scope.ServiceProvider.GetRequiredService<UserSeeder>();

        await userSeeder.EnsureSeedDataAsync().ConfigureAwait(false);
    }

    /// <summary>
    ///     Gets called when webHost is being stopped.
    /// </summary>
    /// <param name="cancellationToken">token use to control async task cancellation.</param>
    /// <returns>Task completion status.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
