using Identity.API.Dtos;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Repo;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity.API.Services.Accounts;

public class AccountService : IAccountService
{
    private readonly Context _context;
    private readonly IConfiguration _config;
    private readonly UserManager<User> _userManager;
    private readonly JWTService _jwtService;

    public AccountService(Context context, IConfiguration config, UserManager<User> userManager, JWTService jwtService)
    {
        _context = context;
        _config = config;
        _userManager = userManager;
        _jwtService = jwtService;
    }

    public async Task<UserDto> RefereshToken(string? token, string? userId)
    {
        bool isValid = await IsValidRefreshTokenAsync(userId, token);

        if (!isValid) throw new Exception("Invalid or expired token, please try to login");

        User? user = await _userManager.FindByIdAsync(userId);
        if (user is null) throw new Exception("User does not exist");

        await SaveRefreshTokenAsync(user);

        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = await _jwtService.CreateJWT(user),
        };
    }

    public async Task<bool> IsValidRefreshTokenAsync(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token)) return false;

        var fetchedRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.UserId == userId && x.Token == token);
        if (fetchedRefreshToken == null) return false;
        if (fetchedRefreshToken.IsExpired) return false;

        return true;
    }

    private async Task SaveRefreshTokenAsync(User user)
    {
        RefreshToken refreshToken = _jwtService.CreateRefreshToken(user);

        var existingRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.UserId == user.Id);
        if (existingRefreshToken is not null)
        {
            existingRefreshToken.Token = refreshToken.Token;
            existingRefreshToken.CreatedAtdUtc = refreshToken.CreatedAtdUtc;
            existingRefreshToken.ExpiresAtUtc = refreshToken.ExpiresAtUtc;
        }
        else
        {
            user.RefreshTokens.Add(refreshToken);
        }

        await _context.SaveChangesAsync();

        var cookieOptions = new CookieOptions
        {
            Expires = refreshToken.ExpiresAtUtc,
            IsEssential = true,
            HttpOnly = true,
        };

        //Response.Cookies.Append("identityAppRefreshToken", refreshToken.Token, cookieOptions);
    }
}
