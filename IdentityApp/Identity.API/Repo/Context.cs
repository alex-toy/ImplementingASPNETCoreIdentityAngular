using Identity.API.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identity.API.Repo;

public class Context : IdentityDbContext<User>
{
    public Context(DbContextOptions<Context> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }
}
