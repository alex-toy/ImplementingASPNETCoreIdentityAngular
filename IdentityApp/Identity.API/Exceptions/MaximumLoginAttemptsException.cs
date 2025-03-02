namespace Identity.API.Exceptions;

public class MaximumLoginAttemptsException : Exception
{
    public DateTimeOffset? UnlockDate { get; }

    public MaximumLoginAttemptsException(DateTimeOffset? unlockDate) : base("maximum_login_attempts")
    {
        UnlockDate = unlockDate;
    }
}
