using Identity.API.Dtos.Account;
using Identity.API.Entities;

namespace Identity.API.Services.JWTs
{
    public interface IJWTService
    {
        Task<UserDto> CreateApplicationUserDto(User user);
        Task<string> CreateJWT(User user);
        RefreshToken CreateRefreshToken(User user);
    }
}