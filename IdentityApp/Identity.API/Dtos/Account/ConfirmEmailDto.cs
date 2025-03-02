using System.ComponentModel.DataAnnotations;

namespace Identity.API.Dtos.Account;

public class ConfirmEmailDto
{
    [Required]
    public required string Token { get; set; }

    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid email address")]
    public required string Email { get; set; }
}
