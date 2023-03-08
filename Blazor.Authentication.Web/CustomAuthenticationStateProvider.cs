namespace Blazor.Authentication.Web;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

using Blazor.Authentication.Web.Data;

using Microsoft.AspNetCore.Components.Authorization;

/// <summary>
/// Custom state authentication state provider.
/// </summary>
public sealed class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly HttpClient client;

    private string? token;

    private string? internalRefreshToken;

    private ClaimsPrincipal? principal;

    public CustomAuthenticationStateProvider(IHttpClientFactory factory) => this.client = factory.CreateClient("identity");

    public string? Email
        => this.principal?.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

    public string? Login
        => this.principal?.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;

    private DateTime tokenExpiration { get; set; }

    /// <inheritdoc />
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var newToken = await this.GetTokenAsync().ConfigureAwait(false);

        var identity = string.IsNullOrEmpty(newToken)
                           ? new()
                           : new ClaimsIdentity(ParseClaimsFromJwt(newToken), "jwt");

        this.principal = new(identity);
        return new(this.principal);
    }

    public async Task<string?> GetTokenAsync()
    {
        if (this.token is null)
            return null;

        if (DateTime.UtcNow >= this.tokenExpiration)
        {
            var result = await this.UpdateTokenAsync().ConfigureAwait(false);

            this.SetToken(result.Token, result.RefreshToken, result.Expiration);
        }

        return this.token;
    }

    public string? GetRefreshToken()
    {
        if (this.token is null)
            return null;

        return this.internalRefreshToken;
    }

    public string SetUserLoggedIn(string? newToken, string? refreshToken, DateTime expiration)
    {
        this.SetToken(newToken, refreshToken, expiration);
        return "/";
    }

    public void LogOutUser()
        => this.SetToken(null, null, DateTime.UtcNow);


    public void SetToken(string? newToken, string? refreshToken, DateTime expiration)
    {
        this.token = newToken;
        this.internalRefreshToken = refreshToken;
        this.tokenExpiration = expiration;

        this.NotifyAuthenticationStateChanged(this.GetAuthenticationStateAsync());
    }

    /// <summary>
    ///     Read JWT to extract claims values.
    /// </summary>
    /// <param name="jwt">JWT as string.</param>
    /// <returns>Collection of claims extracted from JWT.</returns>
    private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        if (string.IsNullOrEmpty(jwt))
            return new List<Claim>();

        var claims = new List<Claim>();
        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);

        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

        if (keyValuePairs == null)
            return new List<Claim>();

        keyValuePairs.TryGetValue(ClaimTypes.Role, out var roles);

        if (roles != null)
        {
            if (roles.ToString()
                    ?.Trim()
                     .StartsWith("[", StringComparison.CurrentCultureIgnoreCase) ?? false)
            {
                var parsedRoles = JsonSerializer.Deserialize<string[]>(roles.ToString()!) ?? Array.Empty<string>();

                claims.AddRange(parsedRoles.Select(parsedRole => new Claim(ClaimTypes.Role, parsedRole)));
            }
            else
            {
                claims.Add(new(ClaimTypes.Role, roles.ToString() ?? string.Empty));
            }

            keyValuePairs.Remove(ClaimTypes.Role);
        }

        claims.AddRange(keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString() ?? string.Empty)));

        return claims;
    }

    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }

        return Convert.FromBase64String(base64);
    }

    /// <summary>
    ///     Method that tries to renew current JWT from Identity server.
    /// </summary>
    /// <returns>tuple with token and expiration date.</returns>
    private async Task<(string? Token, string? RefreshToken, DateTime Expiration)> UpdateTokenAsync()
    {
        var tokenRenewObject = new { ExpiredToken = this.token, RefreshToken = this.internalRefreshToken };

        var json = new StringContent(JsonSerializer.Serialize<dynamic>(tokenRenewObject), Encoding.UTF8, "application/json");

        var identityResult = await this.client
                                       .PostAsync(new Uri("refresh", UriKind.Relative), json)
                                       .ConfigureAwait(false);

        if (identityResult is not { IsSuccessStatusCode: true })
            return (null, null, DateTime.UtcNow);

        var tokenDto = await identityResult.Content.ReadFromJsonAsync<AccountToken>().ConfigureAwait(false);


        return tokenDto switch
        {
            not null => (tokenDto.Token, tokenDto.RefreshToken, tokenDto.ExpirationDate),
            _ => (null, null, DateTime.UtcNow),
        };
    }
}
