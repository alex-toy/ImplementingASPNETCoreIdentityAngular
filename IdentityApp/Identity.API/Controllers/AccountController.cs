using System.Security.Claims;
using System.Text;
using Identity.API.Dtos;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Repo;
using Identity.API.Services;
using Identity.API.Services.Accounts;
using Identity.API.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace Identity.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly JWTService _jwtService;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly EmailService _emailService;
    private readonly Context _context;
    private readonly IConfiguration _config;
    private readonly HttpClient _facebookHttpClient;
    private readonly IAccountService _accountService;

    public AccountController(JWTService jwtService,
        SignInManager<User> signInManager,
        UserManager<User> userManager,
        EmailService emailService,
        Context context,
        IConfiguration config,
        IAccountService accountService)
    {
        _jwtService = jwtService;
        _signInManager = signInManager;
        _userManager = userManager;
        _emailService = emailService;
        _context = context;
        _config = config;
        _facebookHttpClient = new HttpClient
        {
            BaseAddress = new Uri("https://graph.facebook.com")
        };
        _accountService = accountService;
    }

    [Authorize]
    [HttpPost("refresh-token")]
    public async Task<ResponseDto<UserDto>> RefereshToken()
    {
        string? token = Request.Cookies["identityAppRefreshToken"];
        string? userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        try
        {
            UserDto user = await _accountService.RefereshToken(token, userId);
            return new ResponseDto<UserDto> { Data = user, IsSuccess = true };
        }
        catch (Exception ex)
        {
            return new ResponseDto<UserDto> { IsSuccess = false, Message = ex.Message };
        }
    }

    [Authorize]
    [HttpGet("refresh-page")]
    public async Task<ActionResult<UserDto>> RefreshPage()
    {
        User? user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized("You have been locked out");
        }
        return await CreateApplicationUserDto(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.UserName);
        if (user == null) return Unauthorized("Invalid username or password");

        if (user.EmailConfirmed == false) return Unauthorized("Please confirm your email.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

        if (result.IsLockedOut)
        {
            return Unauthorized(string.Format("Your account has been locked. You should wait until {0} (UTC time) to be able to login", user.LockoutEnd));
        }

        if (!result.Succeeded)
        {
            // User has input an invalid password
            if (!user.UserName.Equals(SD.AdminUserName))
            {
                // Increamenting AccessFailedCount of the AspNetUser by 1
                await _userManager.AccessFailedAsync(user);
            }

            if (user.AccessFailedCount >= SD.MaximumLoginAttempts)
            {
                // Lock the user for one day
                await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddDays(1));
                return Unauthorized(string.Format("Your account has been locked. You should wait until {0} (UTC time) to be able to login", user.LockoutEnd));
            }


            return Unauthorized("Invalid username or password");
        }

        await _userManager.ResetAccessFailedCountAsync(user);
        await _userManager.SetLockoutEndDateAsync(user, null);

        return await CreateApplicationUserDto(user);
    }

    //[HttpPost("login-with-third-party")]
    //public async Task<ActionResult<UserDto>> LoginWithThirdParty(LoginWithExternalDto model)
    //{
    //    if (model.Provider.Equals(SD.Facebook))
    //    {
    //        try
    //        {
    //            if (!FacebookValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
    //            {
    //                return Unauthorized("Unable to login with facebook");
    //            }
    //        }
    //        catch (Exception)
    //        {
    //            return Unauthorized("Unable to login with facebook");
    //        }
    //    }
    //    else if (model.Provider.Equals(SD.Google))
    //    {
    //        try
    //        {
    //            if (!GoogleValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
    //            {
    //                return Unauthorized("Unable to login with google");
    //            }
    //        }
    //        catch (Exception)
    //        {
    //            return Unauthorized("Unable to login with google");
    //        }
    //    }
    //    else
    //    {
    //        return BadRequest("Invalid provider");
    //    }

    //    var user = await _userManager.Users.FirstOrDefaultAsync(x => x.UserName == model.UserId && x.Provider == model.Provider);
    //    if (user == null) return Unauthorized("Unable to find your account");

    //    return await CreateApplicationUserDto(user);
    //}

    [HttpPost("register")]
    public async Task<ResponseDto<RegisterResultDto>> Register(RegisterDto register)
    {
        if (await CheckEmailExistsAsync(register.Email))
        {
            return new ResponseDto<RegisterResultDto>
            {
                IsSuccess = false,
                Message = $"An existing account is using {register.Email}, email address. Please try with another email address"
            };
        }

        User userToAdd = register.ToUser();

        IdentityResult result = await _userManager.CreateAsync(userToAdd, register.Password);
        if (!result.Succeeded) return new ResponseDto<RegisterResultDto>
        {
            IsSuccess = false,
            Message = string.Join(", ", result.Errors)
        };
        await _userManager.AddToRoleAsync(userToAdd, SD.PlayerRole);

        try
        {
            //if (await SendConfirmEMailAsync(userToAdd))
            //{
            //    return new ResponseDto<RegisterResultDto>
            //    {
            //        Data = new RegisterResultDto { Title = "Account Created", Message = "Your account has been created, please confrim your email address" },
            //        IsSuccess = true,
            //        Message = "Your account has been created, please confrim your email address"
            //    };
            //}

            return new ResponseDto<RegisterResultDto>
            {
                IsSuccess = false,
                Message = "Failed to send email. Please contact admin"
            };
        }
        catch (Exception ex)
        {
            return new ResponseDto<RegisterResultDto>
            {
                IsSuccess = false,
                Message = ex.Message
            };
        }
    }

    //[HttpPost("register-with-third-party")]
    //public async Task<ActionResult<UserDto>> RegisterWithThirdParty(RegisterWithExternal model)
    //{
    //    if (model.Provider.Equals(SD.Facebook))
    //    {
    //        try
    //        {
    //            if (!FacebookValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
    //            {
    //                return Unauthorized("Unable to register with facebook");
    //            }
    //        }
    //        catch (Exception)
    //        {
    //            return Unauthorized("Unable to register with facebook");
    //        }
    //    }
    //    else if (model.Provider.Equals(SD.Google))
    //    {
    //        try
    //        {
    //            if (!GoogleValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
    //            {
    //                return Unauthorized("Unable to register with google");
    //            }
    //        }
    //        catch (Exception)
    //        {
    //            return Unauthorized("Unable to register with google");
    //        }
    //    }
    //    else
    //    {
    //        return BadRequest("Invalid provider");
    //    }

    //    var user = await _userManager.FindByNameAsync(model.UserId);
    //    if (user != null) return BadRequest(string.Format("You have an account already. Please login with your {0}", model.Provider));

    //    var userToAdd = new User
    //    {
    //        FirstName = model.FirstName.ToLower(),
    //        LastName = model.LastName.ToLower(),
    //        UserName = model.UserId,
    //        Provider = model.Provider,
    //    };

    //    var result = await _userManager.CreateAsync(userToAdd);
    //    if (!result.Succeeded) return BadRequest(result.Errors);
    //    await _userManager.AddToRoleAsync(userToAdd, SD.PlayerRole);

    //    return await CreateApplicationUserDto(userToAdd);
    //}

    [HttpPut("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null) return Unauthorized("This email address has not been registered yet");

        if (user.EmailConfirmed == true) return BadRequest("Your email was confirmed before. Please login to your account");

        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (result.Succeeded)
            {
                return Ok(new JsonResult(new { title = "Email confirmed", message = "Your email address is confirmed. You can login now" }));
            }

            return BadRequest("Invalid token. Please try again");
        }
        catch (Exception)
        {
            return BadRequest("Invalid token. Please try again");
        }
    }

    [HttpPost("resend-email-confirmation-link/{email}")]
    public async Task<IActionResult> ResendEMailConfirmationLink(string email)
    {
        if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email");
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null) return Unauthorized("This email address has not been registerd yet");
        if (user.EmailConfirmed == true) return BadRequest("Your email address was confirmed before. Please login to your account");

        try
        {
            //if (await SendConfirmEMailAsync(user))
            //{
            //    return Ok(new JsonResult(new { title = "Confirmation link sent", message = "Please confirm your email address" }));
            //}

            return BadRequest("Failed to send email. PLease contact admin");
        }
        catch (Exception)
        {
            return BadRequest("Failed to send email. PLease contact admin");
        }
    }

    //[HttpPost("forgot-username-or-password/{email}")]
    //public async Task<IActionResult> ForgotUsernameOrPassword(string email)
    //{
    //    if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email");

    //    var user = await _userManager.FindByEmailAsync(email);

    //    if (user == null) return Unauthorized("This email address has not been registerd yet");
    //    if (user.EmailConfirmed == false) return BadRequest("Please confirm your email address first.");

    //    try
    //    {
    //        if (await SendForgotUsernameOrPasswordEmail(user))
    //        {
    //            return Ok(new JsonResult(new { title = "Forgot username or password email sent", message = "Please check your email" }));
    //        }

    //        return BadRequest("Failed to send email. Please contact admin");
    //    }
    //    catch (Exception)
    //    {
    //        return BadRequest("Failed to send email. Please contact admin");
    //    }
    //}

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null) return Unauthorized("This email address has not been registerd yet");
        if (user.EmailConfirmed == false) return BadRequest("PLease confirm your email address first");

        try
        {
            var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new JsonResult(new { title = "Password reset success", message = "Your password has been reset" }));
            }

            return BadRequest("Invalid token. Please try again");
        }
        catch (Exception)
        {
            return BadRequest("Invalid token. Please try again");
        }
    }

    private async Task<UserDto> CreateApplicationUserDto(User user)
    {
        await SaveRefreshTokenAsync(user);
        return new UserDto
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            JWT = await _jwtService.CreateJWT(user),
        };
    }

    private async Task<bool> CheckEmailExistsAsync(string email)
    {
        return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
    }

    //private async Task<bool> SendConfirmEMailAsync(User user)
    //{
    //    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
    //    token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
    //    var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

    //    var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
    //        "<p>Please confirm your email address by clicking on the following link.</p>" +
    //        $"<p><a href=\"{url}\">Click here</a></p>" +
    //        "<p>Thank you,</p>" +
    //        $"<br>{_config["Email:ApplicationName"]}";

    //    var emailSend = new EmailSendDto() { Body = body, Subject = "Confirm your email", To = user.Email };

    //    return await _emailService.SendEmailAsync(emailSend);
    //}

    //private async Task<bool> SendForgotUsernameOrPasswordEmail(User user)
    //{
    //    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    //    token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
    //    var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

    //    var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
    //       $"<p>Username: {user.UserName}.</p>" +
    //       "<p>In order to reset your password, please click on the following link.</p>" +
    //       $"<p><a href=\"{url}\">Click here</a></p>" +
    //       "<p>Thank you,</p>" +
    //       $"<br>{_config["Email:ApplicationName"]}";

    //    var emailSend = new EmailSendDto { To = user.Email, Subject = "Forgot username or password", Body = body };

    //    return await _emailService.SendEmailAsync(emailSend);
    //}

    private async Task<bool> FacebookValidatedAsync(string accessToken, string userId)
    {
        var facebookKeys = _config["Facebook:AppId"] + "|" + _config["Facebook:AppSecret"];
        var fbResult = await _facebookHttpClient.GetFromJsonAsync<FacebookResultDto>($"debug_token?input_token={accessToken}&access_token={facebookKeys}");

        if (fbResult is null || fbResult.Data.Is_Valid == false || !fbResult.Data.User_Id.Equals(userId))
        {
            return false;
        }

        return true;
    }

    //private async Task<bool> GoogleValidatedAsync(string accessToken, string userId)
    //{
    //    var payload = await GoogleJsonWebSignature.ValidateAsync(accessToken);

    //    if (!payload.Audience.Equals(_config["Google:ClientId"]))
    //    {
    //        return false;
    //    }

    //    if (!payload.Issuer.Equals("accounts.google.com") && !payload.Issuer.Equals("https://accounts.google.com"))
    //    {
    //        return false;
    //    }

    //    if (payload.ExpirationTimeSeconds == null)
    //    {
    //        return false;
    //    }

    //    DateTime now = DateTime.Now.ToUniversalTime();
    //    DateTime expiration = DateTimeOffset.FromUnixTimeSeconds((long)payload.ExpirationTimeSeconds).DateTime;
    //    if (now > expiration)
    //    {
    //        return false;
    //    }

    //    if (!payload.Subject.Equals(userId))
    //    {
    //        return false;
    //    }

    //    return true;
    //}

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

        Response.Cookies.Append("identityAppRefreshToken", refreshToken.Token, cookieOptions);
    }

    public async Task<bool> IsValidRefreshTokenAsync(string userId, string token)
    {
        return await NewMethod(userId, token);
    }

    private async Task<bool> NewMethod(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token)) return false;

        var fetchedRefreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(x => x.UserId == userId && x.Token == token);
        if (fetchedRefreshToken == null) return false;
        if (fetchedRefreshToken.IsExpired) return false;

        return true;
    }
}
