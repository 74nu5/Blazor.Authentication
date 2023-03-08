using Api.Identity.Business;
using Api.Identity.Business.Abstractions;
using Api.Identity.Business.Models;

using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddBusiness();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost(
        "/login",
        async ([FromServices] IAuthenticationBusiness authenticationBusiness, [FromBody] LoginRequest loginModel)
            => await authenticationBusiness.LoginAsync(loginModel).ConfigureAwait(false))
   .WithName("Login")
   .WithOpenApi();

app.MapPost(
        "/refresh",
        async ([FromServices] IAuthenticationBusiness authenticationBusiness, [FromBody] RefreshTokenRequest refreshTokenRequest)
            => await authenticationBusiness.RefreshTokenAsync(refreshTokenRequest.RefreshToken, refreshTokenRequest.ExpiredToken).ConfigureAwait(false))
   .WithName("Refresh")
   .WithOpenApi();

app.Run();