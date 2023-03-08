namespace Api.Identity.Business.Models;

/// <summary>
///     Record which represent the token infos.
/// </summary>
public sealed record TokenInfo
{
    /// <summary>
    ///     Gets the token.
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    ///     Gets the refresh token use to renew an account token.
    /// </summary>
    public required string RefreshToken { get; init; }

    /// <summary>
    ///     Gets the token expiration date.
    /// </summary>
    public required DateTime ExpirationDate { get; init; }
}
