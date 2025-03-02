using System.Security.Claims;
using System.Text;
using Identity.API.Dtos.Account;
using Identity.API.Entities;
using Identity.API.Exceptions;
using Identity.API.Services.Accounts;
using Identity.API.Services.JWTs;
using Identity.API.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace Identity.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly HttpClient _facebookHttpClient;
    private readonly IConfiguration _config;
    private readonly IJWTService _jwtService;
    private readonly IAccountService _accountService;

    public AccountController(IJWTService jwtService,
        SignInManager<User> signInManager,
        UserManager<User> userManager,
        IConfiguration config,
        IAccountService accountService)
    {
        _jwtService = jwtService;
        _signInManager = signInManager;
        _userManager = userManager;
        _config = config;
        _facebookHttpClient = new HttpClient
        {
            BaseAddress = new Uri("https://graph.facebook.com")
        };
        _accountService = accountService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<RegisterResultDto>> Register(RegisterDto register)
    {
        try
        {
            return Ok(await _accountService.Register(register));
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto login)
    {
        try
        {
            return Ok(await _accountService.Login(login));
        }
        catch (LockedOutAccountException ex)
        {
            return Unauthorized(new { ex.Message, LockoutEnd = ex.UnlockDate });
        }
        catch (MaximumLoginAttemptsException ex)
        {
            return Unauthorized(new { ex.Message, LockoutEnd = ex.UnlockDate });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [Authorize]
    [HttpPost("refresh-token")]
    public async Task<ActionResult<UserDto>> RefreshToken()
    {
        string? token = Request.Cookies["identityAppRefreshToken"];
        string? userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (token is null || userId is null) return BadRequest("bad parameters");

        try
        {
            (UserDto user, RefreshToken refreshToken) = await _accountService.RefreshToken(token, userId);
            CookieOptions cookieOptions = new ()
            {
                Expires = refreshToken.ExpiresAtUtc,
                IsEssential = true,
                HttpOnly = true,
            };

            Response.Cookies.Append("identityAppRefreshToken", refreshToken.Token, cookieOptions);
            return user;
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
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
        return await _jwtService.CreateApplicationUserDto(user);
    }

    [HttpPut("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model)
    {
        User? user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null) return Unauthorized("This email address has not been registered yet");

        if (user.EmailConfirmed) return BadRequest("Your email was confirmed before. Please login to your account");

        try
        {
            byte[] decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            string decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, decodedToken);
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
        User? user = await _userManager.FindByEmailAsync(email);

        if (user is null) return Unauthorized("This email address has not been registered yet");
        if (user.EmailConfirmed) return BadRequest("Your email address was confirmed before. Please login to your account");

        try
        {
            if (await _accountService.SendConfirmEMailAsync(user))
            {
                return Ok(new JsonResult(new { title = "Confirmation link sent", message = "Please confirm your email address" }));
            }

            return BadRequest("Failed to send email. PLease contact admin");
        }
        catch (Exception)
        {
            return BadRequest("Failed to send email. PLease contact admin");
        }
    }

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
    {
        User? user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null) return Unauthorized("This email address has not been registerd yet");
        if (!user.EmailConfirmed) return BadRequest("PLease confirm your email address first");

        try
        {
            byte[] decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
            string decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            IdentityResult result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);
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

    //private async Task<bool> FacebookValidatedAsync(string accessToken, string userId)
    //{
    //    var facebookKeys = _config["Facebook:AppId"] + "|" + _config["Facebook:AppSecret"];
    //    var fbResult = await _facebookHttpClient.GetFromJsonAsync<FacebookResultDto>($"debug_token?input_token={accessToken}&access_token={facebookKeys}");

    //    if (fbResult is null || fbResult.Data.Is_Valid == false || !fbResult.Data.User_Id.Equals(userId))
    //    {
    //        return false;
    //    }

    //    return true;
    //}

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
}
