namespace Blazor.Authentication.Web.Public.Auth;

using System.Text.Json;
using System.Text;

using Blazor.Authentication.Web.Data;

using Microsoft.AspNetCore.Components;

public partial class Login
{
    [Inject]
    public IHttpClientFactory Factory { get; set; }

    [Inject]
    public CustomAuthenticationStateProvider AuthProvider { get; set; } = null!;


    private LoginViewModel loginModel = new();

    private async Task LoginAsync()
    {
        var client = this.Factory.CreateClient("identity");
        var json = new StringContent(JsonSerializer.Serialize(loginModel), Encoding.UTF8, "application/json");

        var responseMessage = await client.PostAsync("/login", json);

        var str = await responseMessage.Content.ReadAsStringAsync();

        var tokenInfo = JsonSerializer.Deserialize<AccountToken>(str);
        this.AuthProvider.SetUserLoggedIn(tokenInfo.Token, tokenInfo.RefreshToken, tokenInfo.ExpirationDate);
    }
}
