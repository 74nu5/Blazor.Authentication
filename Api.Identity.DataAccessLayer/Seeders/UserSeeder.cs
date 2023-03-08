namespace Api.Identity.DataAccessLayer.Seeders;

using Api.Identity.DataAccessLayer.Entities;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

/// <summary>
///     Class which defines user seeder.
/// </summary>
public sealed class UserSeeder
{
    private const string DefaultLogin = "admin";

    private readonly ILogger<UserSeeder> logger;
    private readonly UserManager<User> personalAccountManager;

    private readonly RoleManager<IdentityRole> roleManager;

    private readonly IPasswordHasher<User> passwordHasher;

    /// <summary>
    ///     Initializes a new instance of the <see cref="UserSeeder" /> class.
    /// </summary>
    /// <param name="logger">The logging service.</param>
    /// <param name="personalAccountManager">The personal account manager.</param>
    /// <param name="roleManager">The role manager.</param>
    /// <param name="passwordHasher">The password hasher service.</param>
    public UserSeeder(
        ILogger<UserSeeder> logger,
        UserManager<User> personalAccountManager,
        RoleManager<IdentityRole> roleManager,
        IPasswordHasher<User> passwordHasher)
    {
        this.logger = logger;
        this.personalAccountManager = personalAccountManager;
        this.roleManager = roleManager;
        this.passwordHasher = passwordHasher;
    }

    /// <summary>
    ///     Ensure that there is a root user in database context.
    /// </summary>
    /// <returns>
    ///     Returns the result of the asynchronous operation.
    /// </returns>
    public async Task EnsureSeedDataAsync()
    {
        await this.SeedRootUserAsync().ConfigureAwait(false);
    }

    /// <summary>
    ///     Seeds the root user if it not exists.
    /// </summary>
    /// <returns>
    ///     Returns the result of the asynchronous operation.
    /// </returns>
    private async Task SeedRootUserAsync()
    {
        // Searching for root user
        var adminUser = await this.personalAccountManager.FindByNameAsync(DefaultLogin).ConfigureAwait(false);

        if (adminUser is not null)
            return;

        // Create it
        var guidUser = Guid.NewGuid().ToString();
        adminUser = new()
        {
            Id = guidUser,
            UserName = DefaultLogin,
            Email = "admin@test.fr",
        };

        adminUser.PasswordHash = this.passwordHasher.HashPassword(adminUser, @"Password1234");

        var identityResult = await this.personalAccountManager.CreateAsync(adminUser).ConfigureAwait(false);
        if (!identityResult.Succeeded)
        {
            this.logger.LogError("Seeding errors {errors}", string.Join("\n", identityResult.Errors));
            return;
        }

        var rootIdentityUser = await this.personalAccountManager.FindByNameAsync(DefaultLogin).ConfigureAwait(false);
        if (rootIdentityUser is null)
        {
            this.logger.LogError("Admin not seed.");
            return;
        }

        this.logger.LogInformation("Root user created");
    }
}
