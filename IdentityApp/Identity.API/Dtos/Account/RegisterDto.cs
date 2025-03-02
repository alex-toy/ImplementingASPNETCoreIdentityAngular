using System.ComponentModel.DataAnnotations;
using Identity.API.Entities;

namespace Identity.API.Dtos.Account;

public class RegisterDto
{
    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "First name must be at least {2}, and maximum {1} characters")]
    public required string FirstName { get; set; }

    [Required]
    [StringLength(15, MinimumLength = 3, ErrorMessage = "Last name must be at least {2}, and maximum {1} characters")]
    public required string LastName { get; set; }

    [Required]
    [RegularExpression("^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$", ErrorMessage = "Invalid email address")]
    public required string Email { get; set; }

    [Required]
    [StringLength(15, MinimumLength = 6, ErrorMessage = "Password must be at least {2}, and maximum {1} characters")]
    public required string Password { get; set; }

    public User ToUser()
    {
        return new User
        {
            FirstName = FirstName.ToLower(),
            LastName = LastName.ToLower(),
            UserName = Email.ToLower(),
            Email = Email.ToLower(),
        };
    }
}
