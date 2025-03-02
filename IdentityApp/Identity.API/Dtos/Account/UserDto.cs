namespace Identity.API.Dtos.Account;

public class UserDto
{
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public required string JWT { get; set; }
}
