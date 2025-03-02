namespace Identity.API.Exceptions;

public class LockedOutAccountException : Exception
{
    public DateTimeOffset? UnlockDate { get; }

    public LockedOutAccountException(DateTimeOffset? unlockDate) : base("account_locked")
    {
        UnlockDate = unlockDate;
    }
}
