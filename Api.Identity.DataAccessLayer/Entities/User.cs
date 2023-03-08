namespace Api.Identity.DataAccessLayer.Entities;

using Microsoft.AspNetCore.Identity;

public class User : IdentityUser
{
    public string? RefreshToken { get; set; }

    public DateTime? RefreshTokenExpires { get; set; }
}
