using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace TheSprayer.Models
{
    public class CredentialAttempt
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool Success { get; set; }
        public DateTime LastSprayTime { get; set; }
    }
}
