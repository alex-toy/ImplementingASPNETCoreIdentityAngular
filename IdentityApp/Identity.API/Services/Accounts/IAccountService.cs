using Identity.API.Dtos;
using Identity.API.Dtos.Account;

namespace Identity.API.Services.Accounts
{
    public interface IAccountService
    {
        Task<bool> IsEmailExistsAsync(string email);
        Task<bool> IsValidRefreshTokenAsync(string userId, string token);
        Task<UserDto> RefreshToken(string? token, string? userId);
        Task<RegisterResultDto> Register(RegisterDto register);
    }
}