namespace Identity.API.Dtos.Account;

public class EmailSendDto
{
    public required string To { get; set; }
    public required string Subject { get; set; }
    public required string Body { get; set; }
}
