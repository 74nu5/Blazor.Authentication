namespace Api.Identity.Business.Abstractions;

using Api.Identity.Business.Models;

public interface IAuthenticationBusiness
{
    /// <summary>
    ///     Authentication process using basic core identity provider service.
    /// </summary>
    /// <param name="login">The login infos.</param>
    /// <returns>Returns a <seealso cref="TokenInfo" /> if user exists and password is valid, null otherwise.</returns>
    Task<TokenInfo?> LoginAsync(LoginRequest login);

    /// <summary>
    ///     Computes e new token with an expiration date from an old token.
    /// </summary>
    /// <param name="refreshToken">the refresh token needed to renew a token.</param>
    /// <param name="expiredToken">expired token to renew.</param>
    /// <returns>Return a token and the associated expiration date. Can be null if user is unauthorized.</returns>
    Task<TokenInfo?> RefreshTokenAsync(string refreshToken, string expiredToken);

}
