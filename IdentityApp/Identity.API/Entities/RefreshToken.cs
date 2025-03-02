using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Identity.API.Entities;

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public string? UserId { get; set; }

    [Required]
    [StringLength(100)]
    public required string Token { get; set; }

    public DateTime CreatedAtdUtc { get; set; } = DateTime.UtcNow;

    public DateTime ExpiresAtUtc { get; set; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;

    [ForeignKey("UserId")]
    public required User User { get; set; }
}
