namespace Api.Identity.Business.Models;

using System.ComponentModel.DataAnnotations;

/// <summary>
///     Record which defines the necessaray entries for the account login endpoint.
/// </summary>
public record LoginRequest
{
    /// <summary>
    ///     Gets the account login.
    /// </summary>
    [Required]
    public string Login { get; init; } = string.Empty;

    /// <summary>
    ///     Gets the password.
    /// </summary>
    [Required]
    public string Password { get; init; } = string.Empty;
}
