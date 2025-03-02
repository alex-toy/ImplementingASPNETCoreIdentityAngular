using System.ComponentModel.DataAnnotations;

namespace Identity.API.Dtos.Account;

public class LoginWithExternalDto
{
    [Required]
    public required string AccessToken { get; set; }

    [Required]
    public required string UserId { get; set; }

    [Required]
    public required string Provider { get; set; }
}
