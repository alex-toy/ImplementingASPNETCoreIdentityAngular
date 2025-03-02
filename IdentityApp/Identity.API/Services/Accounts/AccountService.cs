using System.Text;
using Identity.API.Dtos;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Repo;
using Identity.API.Services.Emails;
using Identity.API.Services.JWTs;
using Identity.API.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace Identity.API.Services.Accounts;

public class AccountService : IAccountService
{
    private readonly Context _context;
    private readonly IConfiguration _config;
    private readonly UserManager<User> _userManager;
    private readonly IJWTService _jwtService;
    private readonly IEmailService _emailService;

    public AccountService(Context context, IConfiguration config, UserManager<User> userManager, IJWTService jwtService, IEmailService emailService)
    {
        _context = context;
        _config = config;
        _userManager = userManager;
        _jwtService = jwtService;
        _emailService = emailService;
    }

    public async Task<RegisterResultDto> Register(RegisterDto register)
    {
        if (await IsEmailExistsAsync(register.Email)) throw new Exception($"An existing account is using {register.Email}, email address. Please try with another email address");

        User userToAdd = register.ToUser();

        IdentityResult result = await _userManager.CreateAsync(userToAdd, register.Password);
        if (!result.Succeeded) throw new Exception(string.Join(", ", result.Errors));

        await _userManager.AddToRoleAsync(userToAdd, SD.PlayerRole);

        bool isAdded = await SendConfirmEMailAsync(userToAdd);

        if (!isAdded) throw new Exception("Failed to send email. Please contact admin");

        return new RegisterResultDto { Title = "Account Created", Message = "Your account has been created, please confrim your email address" };
    }

    public async Task<UserDto> RefreshToken(string? token, string? userId)
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

    public async Task<bool> IsEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
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

    private async Task<bool> SendConfirmEMailAsync(User user)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

        var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
            "<p>Please confirm your email address by clicking on the following link.</p>" +
            $"<p><a href=\"{url}\">Click here</a></p>" +
            "<p>Thank you,</p>" +
            $"<br>{_config["Email:ApplicationName"]}";

        var emailSend = new EmailSendDto() { Body = body, Subject = "Confirm your email", To = user.Email };

        return await _emailService.SendEmailAsync(emailSend);
    }

    private async Task<bool> SendForgotUsernameOrPasswordEmail(User user)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

        var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
           $"<p>Username: {user.UserName}.</p>" +
           "<p>In order to reset your password, please click on the following link.</p>" +
           $"<p><a href=\"{url}\">Click here</a></p>" +
           "<p>Thank you,</p>" +
           $"<br>{_config["Email:ApplicationName"]}";

        var emailSend = new EmailSendDto { To = user.Email, Subject = "Forgot username or password", Body = body };

        return await _emailService.SendEmailAsync(emailSend);
    }

    private async Task<bool> CheckEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }
}
