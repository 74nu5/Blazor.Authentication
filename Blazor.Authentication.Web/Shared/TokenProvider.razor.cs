namespace Blazor.Authentication.Web.Shared;

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

public partial class TokenProvider
{
    private const string LoginPurpose = "login";
    private const string AccountTokenKey = "accountToken";

    private const string RefreshTokenKey = "refreshToken";

    private const string AuthTokenExpires = "tokenExpires";


    [Parameter]
    public RenderFragment ChildContent { get; set; }

    /// <summary>
    ///     Gets or sets the authentication token retrieved from localStorage.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    ///     Gets or sets the refresh token retrieved from localStorage.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    ///     GEts or sets the authentication token expiration date retrieved from local storage.
    /// </summary>
    public DateTime ExpirationDate { get; set; } = DateTime.UtcNow;

    /// <summary>
    ///     Gets or sets the local storage service.
    /// </summary>
    [Inject]
    public ProtectedLocalStorage LocalStorage { get; set; } = null!;

    /// <summary>
    ///     Gets or sets the authentication state provider..
    /// </summary>
    [Inject]
    public CustomAuthenticationStateProvider AuthProvider { get; set; } = null!;

    /// <summary>
    ///     Gets or sets the logging service.
    /// </summary>
    [Inject]
    public ILogger<TokenProvider> Logger { get; set; } = null!;


    /// <inheritdoc />
    protected override async Task OnInitializedAsync()
    {
        this.AuthProvider.AuthenticationStateChanged += this.OnAuthProviderOnAuthenticationStateChangedAsync;

        try
        {
            var tokenRetriever = await this.LocalStorage.GetAsync<string>(LoginPurpose, AccountTokenKey).ConfigureAwait(true);
            if (tokenRetriever is { Success: true, Value: { } })
                this.Token = tokenRetriever.Value;

            var refreshTokenRetriever = await this.LocalStorage.GetAsync<string>(LoginPurpose, RefreshTokenKey).ConfigureAwait(true);
            if (refreshTokenRetriever is { Success: true, Value: { } })
                this.RefreshToken = refreshTokenRetriever.Value;

            var expirationDateRetriever = await this.LocalStorage.GetAsync<DateTime>(LoginPurpose, AuthTokenExpires).ConfigureAwait(true);
            if (expirationDateRetriever.Success)
                this.ExpirationDate = expirationDateRetriever.Value;
        }
        catch (Exception)
        {
            await this.SaveChangesAsync().ConfigureAwait(true);
        }
    }

    /// <summary>
    ///     Stores token and expiration date in local storage.
    ///     When <seealso cref="Token" /> is null information are removed from local storage.
    /// </summary>
    /// <returns>
    ///     result of the asynchronous operation.
    /// </returns>
    public async Task SaveChangesAsync()
    {
        try
        {
            if (this.Token is null || this.RefreshToken is null)
            {
                await this.LocalStorage.DeleteAsync(AccountTokenKey).ConfigureAwait(true);
                await this.LocalStorage.DeleteAsync(RefreshTokenKey).ConfigureAwait(true);
                await this.LocalStorage.DeleteAsync(AuthTokenExpires).ConfigureAwait(true);
            }
            else
            {
                await this.LocalStorage.SetAsync(LoginPurpose, AccountTokenKey, this.Token).ConfigureAwait(true);
                await this.LocalStorage.SetAsync(LoginPurpose, RefreshTokenKey, this.RefreshToken).ConfigureAwait(true);
                await this.LocalStorage.SetAsync(LoginPurpose, AuthTokenExpires, this.ExpirationDate).ConfigureAwait(true);
            }
        }
        catch (Exception ex)
        {
            this.Logger.LogError(ex, "Error occurred while saving data into local storage.");
        }

    }

    private async void OnAuthProviderOnAuthenticationStateChangedAsync(Task<AuthenticationState> task)
    {
        try
        {
            await this.AuthProvider_AuthenticationStateChangedAsync(task).ConfigureAwait(true);
        }
        catch (Exception e)
        {
            this.Logger.LogError(e, "An error occurs when token provide process.");
        }
    }

    private async Task AuthProvider_AuthenticationStateChangedAsync(Task<AuthenticationState> task)
    {
        var identity = await task;
        if (identity.User.Identity?.IsAuthenticated ?? false)
        {
            var expTimestamp = identity.User.Claims.FirstOrDefault(claim => claim.Type == "exp")
                                      ?.Value;

            this.ExpirationDate = double.TryParse(expTimestamp, out var convertedExpTimestamp)
                                      ? ToDateTime(convertedExpTimestamp)
                                      : DateTime.UtcNow;

            this.Token = await this.AuthProvider.GetTokenAsync().ConfigureAwait(true);
            this.RefreshToken = this.AuthProvider.GetRefreshToken();
        }
        else
        {
            this.Token = null;
            this.RefreshToken = null;
        }

        // Store info in local storage
        await this.SaveChangesAsync().ConfigureAwait(true);
    }

    private static DateTime ToDateTime(double unixTimeStamp)
    {
        // Unix timestamp is seconds past epoch
        var dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToUniversalTime();

        return dtDateTime;
    }
}
