using System.Text;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Exceptions;
using Identity.API.Repo;
using Identity.API.Services.Emails;
using Identity.API.Services.JWTs;
using Identity.API.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace Identity.API.Services.Accounts;

public class AccountService : IAccountService
{
    private readonly Context _context;
    private readonly IConfiguration _config;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IJWTService _jwtService;
    private readonly IEmailService _emailService;

    public AccountService(Context context, IConfiguration config, UserManager<User> userManager, IJWTService jwtService, IEmailService emailService, SignInManager<User> signInManager)
    {
        _context = context;
        _config = config;
        _userManager = userManager;
        _jwtService = jwtService;
        _emailService = emailService;
        _signInManager = signInManager;
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

    public async Task<UserDto> Login(LoginDto login)
    {
        User? user = await _userManager.FindByNameAsync(login.UserName);
        if (user is null) throw new Exception("invalid_username");

        if (!user.EmailConfirmed) throw new Exception("confirm_email");

        SignInResult result = await _signInManager.CheckPasswordSignInAsync(user, login.Password, false);

        if (result.IsLockedOut) throw new LockedOutAccountException(user.LockoutEnd);

        if (!result.Succeeded)
        {
            if (user.UserName is null) throw new Exception("invalid_username");

            if (!user.UserName.Equals(SD.AdminUserName))
            {
                await _userManager.AccessFailedAsync(user);
            }

            if (user.AccessFailedCount >= SD.MaximumLoginAttempts)
            {
                await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(1));
                throw new MaximumLoginAttemptsException(user.LockoutEnd);
            }

            throw new Exception("invalid_username");
        }

        await _userManager.ResetAccessFailedCountAsync(user);
        await _userManager.SetLockoutEndDateAsync(user, null);

        return await _jwtService.CreateApplicationUserDto(user);
    }

    public async Task<(UserDto, RefreshToken)> RefreshToken(string token, string userId)
    {
        User? user = await _userManager.FindByIdAsync(userId);
        if (user is null) throw new Exception("User does not exist");

        bool isValid = await IsValidRefreshTokenAsync(userId, token);

        if (!isValid) throw new Exception("Invalid or expired token, please try to login");

        RefreshToken refreshToken = await SaveRefreshTokenAsync(user);

        return (new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = await _jwtService.CreateJWT(user),
        }, refreshToken);
    }

    public async Task<bool> IsValidRefreshTokenAsync(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token)) return false;

        RefreshToken? fetchedRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.UserId == userId && x.Token == token);

        return fetchedRefreshToken is not null && !fetchedRefreshToken.IsExpired;
    }

    public async Task<bool> IsEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }

    public async Task<bool> SendConfirmEMailAsync(User user)
    {
        string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        string url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

        string body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
            "<p>Please confirm your email address by clicking on the following link.</p>" +
            $"<p><a href=\"{url}\">Click here</a></p>" +
            "<p>Thank you,</p>" +
            $"<br>{_config["Email:ApplicationName"]}";

        EmailSendDto emailSend = new () { Body = body, Subject = "Confirm your email", To = user.Email };

        return await _emailService.SendEmailAsync(emailSend);
    }

    public async Task<bool> SendForgotUsernameOrPasswordEmail(User user)
    {
        string token = await _userManager.GeneratePasswordResetTokenAsync(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        string url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

        string body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
           $"<p>Username: {user.UserName}.</p>" +
           "<p>In order to reset your password, please click on the following link.</p>" +
           $"<p><a href=\"{url}\">Click here</a></p>" +
           "<p>Thank you,</p>" +
           $"<br>{_config["Email:ApplicationName"]}";

        EmailSendDto emailSend = new EmailSendDto { To = user.Email, Subject = "Forgot username or password", Body = body };

        return await _emailService.SendEmailAsync(emailSend);
    }

    private async Task<bool> CheckEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }

    private async Task<RefreshToken> SaveRefreshTokenAsync(User user)
    {
        RefreshToken refreshToken = _jwtService.CreateRefreshToken(user);

        RefreshToken? existingRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.UserId == user.Id);
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

        return refreshToken;
    }
}
