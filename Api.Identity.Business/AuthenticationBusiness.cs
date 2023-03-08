namespace Api.Identity.Business;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Api.Identity.Business.Abstractions;
using Api.Identity.Business.Models;
using Api.Identity.DataAccessLayer.Entities;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Authentication business.
/// </summary>
public sealed class AuthenticationBusiness : IAuthenticationBusiness
{
    public const string AccountIdentifier = "Identifier";

    private readonly IConfiguration configuration;

    private readonly ILogger<AuthenticationBusiness> logger;

    private readonly UserManager<User> userManager;

    private readonly SignInManager<User> signInManager;

    public AuthenticationBusiness(IConfiguration configuration, ILogger<AuthenticationBusiness> logger, UserManager<User> userManager, SignInManager<User> signInManager)
    {
        this.configuration = configuration;
        this.logger = logger;
        this.userManager = userManager;
        this.signInManager = signInManager;
    }

    /// <inheritdoc />
    public async Task<TokenInfo?> LoginAsync(LoginRequest login)
    {
        this.logger.LogDebug("Login ask for {login}", login.Login);

        var user = await this.userManager.FindByNameAsync(login.Login).ConfigureAwait(false);

        if (user is null)
        {
            user = await this.userManager.FindByEmailAsync(login.Login).ConfigureAwait(false);

            if (user is null)
                return null;
        }

        if (await this.userManager.IsLockedOutAsync(user).ConfigureAwait(false))
            return null;

        var signInResult = await this.signInManager.CheckPasswordSignInAsync(user, login.Password, false).ConfigureAwait(false);

        if (!signInResult.Succeeded)
            return null;

        var userClaims = await this.BuildClaimsAsync(user).ConfigureAwait(false);

        var loginOut = this.GetToken(userClaims);

        user.RefreshToken = loginOut.RefreshToken;
        user.RefreshTokenExpires = DateTime.UtcNow.AddDays(1);
        _ = await this.userManager.UpdateAsync(user).ConfigureAwait(false);

        return loginOut;
    }

    /// <inheritdoc />
    public async Task<TokenInfo?> RefreshTokenAsync(string refreshToken, string expiredToken)
    {
        var oldToken = new JwtSecurityTokenHandler().ReadJwtToken(expiredToken);

        // Search the user name is sub claim
        var claimSub = oldToken.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sub);

        if (claimSub == null)
            return null;

        this.logger.LogDebug("Refresh token ask for {user}", claimSub.Value);

        var user = await this.userManager.FindByIdAsync(claimSub.Value).ConfigureAwait(false);

        if (user == null)
            return null;

        if (user.RefreshToken != refreshToken || user.RefreshTokenExpires <= DateTime.UtcNow)
            return null;

        var claims = await this.BuildClaimsAsync(user).ConfigureAwait(false);
        var loginOut = this.GetToken(claims);

        user.RefreshToken = loginOut.RefreshToken;
        user.RefreshTokenExpires = DateTime.UtcNow.AddDays(1);
        _ = await this.userManager.UpdateAsync(user).ConfigureAwait(false);

        return loginOut;
    }

    /// <summary>
    ///     Computes claims for the given user.
    /// </summary>
    /// <param name="user">User used to compute claims.</param>
    /// <returns>Returns an <seealso cref="IEnumerable{Claims}" />.</returns>
    private async Task<IEnumerable<Claim>> BuildClaimsAsync(User user)
    {
        var customClaims = new[]
        {
            new Claim(AccountIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
            new Claim(ClaimTypes.PrimarySid, user.Id),
            new Claim(ClaimTypes.MobilePhone, user.PhoneNumber ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        };



        return customClaims;
    }

    /// <summary>
    ///     Computes a token with an expiration date for given claims.
    /// </summary>
    /// <param name="userClaims">claims to include in the token.</param>
    /// <returns>Return a token and the associated expiration date.</returns>
    private TokenInfo GetToken(IEnumerable<Claim> userClaims)
    {
        // This two lines of code define the signing key and algorithm which being use as the token credentials
        var securityKey = this.configuration.GetValue<string>("Jwt:SecurityKey");

        if (securityKey is null)
            throw new InvalidOperationException("SecurityKey isn't defined.");

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));

        var tokenCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var expirationDate = DateTime.UtcNow.AddSeconds(this.configuration.GetValue<int>("Jwt:ExpiryInSeconds"));

        var token = new JwtSecurityToken(
            this.configuration.GetValue<string>("Jwt:Issuer"),
            this.configuration.GetValue<string>("Jwt:Audience"),
            userClaims,
            expires: expirationDate,
            signingCredentials: tokenCredentials);

        return new()
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            ExpirationDate = expirationDate,
        };
    }
}
