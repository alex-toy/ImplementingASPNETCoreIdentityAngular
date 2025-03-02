using System.ComponentModel.DataAnnotations;

namespace Identity.API.Dtos.Account;

public class ResetPasswordDto
{
    [Required]
    public required string Token { get; set; }

    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid email address")]
    public required string Email { get; set; }

    [Required]
    [StringLength(15, MinimumLength = 6, ErrorMessage = "New Password must be at least {2}, and maximum {1} characters")]
    public required string NewPassword { get; set; }
}
