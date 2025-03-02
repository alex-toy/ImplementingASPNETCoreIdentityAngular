using Azure;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Repo;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.API.Services.JWTs;

public class JWTService : IJWTService
{
    private readonly IConfiguration _config;
    private readonly Context _context;
    private readonly UserManager<User> _userManager;
    private readonly SymmetricSecurityKey _jwtKey;

    public JWTService(IConfiguration config, UserManager<User> userManager, Context context)
    {
        _config = config;
        _userManager = userManager;

        // jwtKey is used for both encripting and decripting the JWT token
        _jwtKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]));
        _context = context;
    }
    public async Task<string> CreateJWT(User user)
    {
        var userClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.UserName),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName)
        };

        var roles = await _userManager.GetRolesAsync(user);
        userClaims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var creadentials = new SigningCredentials(_jwtKey, SecurityAlgorithms.HmacSha512Signature);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(userClaims),
            Expires = DateTime.UtcNow.AddMinutes(int.Parse(_config["JWT:ExpiresInMinutes"])),
            SigningCredentials = creadentials,
            Issuer = _config["JWT:Issuer"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(jwt);
    }

    public RefreshToken CreateRefreshToken(User user)
    {
        var token = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(token);

        var refreshToken = new RefreshToken()
        {
            Token = Convert.ToBase64String(token),
            User = user,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(int.Parse(_config["JWT:RefreshTokenExpiresInDays"]))
        };

        return refreshToken;
    }

    public async Task<UserDto> CreateApplicationUserDto(User user)
    {
        await SaveRefreshTokenAsync(user);
        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = await CreateJWT(user),
        };
    }

    private async Task SaveRefreshTokenAsync(User user)
    {
        RefreshToken refreshToken = CreateRefreshToken(user);

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
