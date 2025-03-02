using System.ComponentModel.DataAnnotations;

namespace Identity.API.Dtos.Account;

public class LoginDto
{
    [Required(ErrorMessage = "Username is required")]
    public required string UserName { get; set; }

    [Required]
    public required string Password { get; set; }
}
