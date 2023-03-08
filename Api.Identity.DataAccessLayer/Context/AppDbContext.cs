namespace Api.Identity.DataAccessLayer.Context;

using Api.Identity.DataAccessLayer.Entities;

using Microsoft.EntityFrameworkCore;

/// <summary>
///     Represents the application Database.
/// </summary>
public class AppDbContext : DbContext
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AppDbContext" /> class.
    /// </summary>
    /// <param name="options">The db context options.</param>
    public AppDbContext(DbContextOptions options)
        : base(options)
    {
    }

    /// <summary>
    ///     Gets the accounts set.
    /// </summary>
    public DbSet<User> Users => this.Set<User>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}
