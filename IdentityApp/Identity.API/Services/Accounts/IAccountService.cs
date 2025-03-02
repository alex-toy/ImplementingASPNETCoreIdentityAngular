using Identity.API.Dtos;
using Identity.API.Dtos.Account;
using Identity.API.Entities;

namespace Identity.API.Services.Accounts
{
    public interface IAccountService
    {
        Task<bool> IsEmailExistsAsync(string email);
        Task<bool> IsValidRefreshTokenAsync(string userId, string token);
        Task<UserDto> Login(LoginDto login);
        Task<(UserDto, RefreshToken)> RefreshToken(string token, string userId);
        Task<RegisterResultDto> Register(RegisterDto register);
        Task<bool> SendConfirmEMailAsync(User user);
        Task<bool> SendForgotUsernameOrPasswordEmail(User user);
    }
}