using Identity.API.Dtos;
using Identity.API.Dtos.Account;

namespace Identity.API.Services.Accounts
{
    public interface IAccountService
    {
        Task<bool> IsValidRefreshTokenAsync(string userId, string token);
        Task<UserDto> RefereshToken(string? token, string? userId);
    }
}