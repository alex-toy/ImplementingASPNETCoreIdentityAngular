using Identity.API.Dtos.Account;

namespace Identity.API.Services.Emails
{
    public interface IEmailService
    {
        Task<bool> SendEmailAsync(EmailSendDto emailSend);
    }
}