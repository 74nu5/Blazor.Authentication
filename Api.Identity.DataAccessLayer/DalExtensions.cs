namespace Api.Identity.DataAccessLayer;


using Api.Identity.DataAccessLayer.Context;
using Api.Identity.DataAccessLayer.Seeders;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class DalExtensions
{
    public static void AddDal(this IServiceCollection services)
    {
        services.AddHostedService<InitializeDb>();
        services.TryAddScoped<UserSeeder>();
        services.AddDbContext<AppDbContext>(builder => builder.UseSqlite("Data Source=Formation.Identity.db"));
    }
}
