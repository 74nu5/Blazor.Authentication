namespace Api.Identity.Business.Models;

using System.ComponentModel.DataAnnotations;

/// <summary>
///     Record which defines the necessaray entries for the renew token endpoint.
/// </summary>
public record RefreshTokenRequest
{
    /// <summary>
    ///     Gets the account expired token.
    /// </summary>
    [Required]
    public string ExpiredToken { get; init; } = string.Empty;

    /// <summary>
    ///     Gets the refresh token which is use to validate the renewal request.
    /// </summary>
    [Required]
    public string RefreshToken { get; init; } = string.Empty;
}
