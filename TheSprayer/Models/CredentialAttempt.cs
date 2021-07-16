using System;
using System.ComponentModel.DataAnnotations;

namespace TheSprayer.Models
{
    public class CredentialAttempt
    {
        [Key]
        public string Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public DateTime LastSprayTime { get; set; }
    }
}
