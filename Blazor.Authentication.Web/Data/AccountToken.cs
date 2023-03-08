namespace Blazor.Authentication.Web.Data;

using System.Text.Json.Serialization;

/// <summary>
///     Class which represents the login response.
/// </summary>
public sealed class AccountToken 
{
    /// <summary>
    ///     Gets or sets the account token use betwwen the frontend and the backend systems.
    /// </summary>
    [JsonPropertyName("token")]
    public string? Token { get; set; }

    /// <summary>
    ///     Gets or sets the refresh token to be used only when account token is expired and need to be renewed..
    /// </summary>
    [JsonPropertyName("refreshToken")]
    public string? RefreshToken { get; set; }

    /// <summary>
    ///     Gets or sets the expiration date.
    /// </summary>
    [JsonPropertyName("expirationDate")]
    public DateTime ExpirationDate { get; set; }
}
