namespace Api.Identity.Business;

using Api.Identity.Business.Abstractions;
using Api.Identity.DataAccessLayer;
using Api.Identity.DataAccessLayer.Context;
using Api.Identity.DataAccessLayer.Entities;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class BusinessExtensions
{
    public static void AddBusiness(this IServiceCollection services)
    {
        services.AddDal();

        _ = services.AddIdentity<User, IdentityRole>(ConfigureIdentity)
                    .AddRoles<IdentityRole>()
                    .AddEntityFrameworkStores<AppDbContext>()
                    .AddDefaultTokenProviders();

        services.TryAddScoped<IAuthenticationBusiness, AuthenticationBusiness>();
    }

    private static void ConfigureIdentity(IdentityOptions opt)
    {
        opt.Tokens.EmailConfirmationTokenProvider = "tokensEmailConfirmationTokenProvider";
        opt.SignIn.RequireConfirmedAccount = false;
        opt.SignIn.RequireConfirmedEmail = false;
        opt.SignIn.RequireConfirmedPhoneNumber = false;
        opt.User.RequireUniqueEmail = true;
        opt.Password.RequireNonAlphanumeric = false;
        opt.Password.RequireDigit = true;
        opt.Password.RequireLowercase = true;
        opt.Password.RequireUppercase = true;
        opt.Password.RequiredLength = 6;
    }
}
