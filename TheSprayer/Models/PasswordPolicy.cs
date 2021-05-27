namespace TheSprayer.Models
{
    public class PasswordPolicy
    {
        public string Name { get; set; }
        public int Precedence { get; set; }
        public double PasswordMaxAge { get; set; }
        public double PasswordMinAge { get; set; }
        public int PasswordMinLength { get; set; }
        public int PasswordHistoryLength { get; set; }
        public int LockoutThreshold { get; set; }
        public double LockoutDuration { get; set; }
        public double ObservationWindow { get; set; }
        public bool IsComplexityRequired { get; set; }
        public bool IsEncryptionReversible { get; set; }
    }
}
