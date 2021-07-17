using System;
using TheSprayer.Models;

namespace TheSprayer.Helpers
{
    public static class ConsoleHelpers
    {
        public static void PrintPasswordPolicy(PasswordPolicy policy)
        {
            Console.WriteLine($"-----{policy.Name}-----");
            Console.WriteLine($"Password Min Length: {policy.PasswordMinLength}");
            Console.WriteLine($"Password Min Age: {policy.PasswordMinAge}");
            Console.WriteLine($"Password Max Age: {policy.PasswordMaxAge}");
            Console.WriteLine($"Password History: {policy.PasswordHistoryLength}");
            Console.WriteLine($"Lockout Duration: {policy.LockoutDuration} minutes");
            Console.WriteLine($"Lockout Threshold: {policy.LockoutThreshold} attempts");
            Console.WriteLine($"Lockout Reset: {policy.ObservationWindow} minutes");
            Console.WriteLine($"Complexity Required: {policy.IsComplexityRequired}");
            Console.WriteLine($"Reversible Encryption: {policy.IsEncryptionReversible}");
            Console.WriteLine($"Precedence: {policy.Precedence}");
        }
    }

    public static class ColorConsole
    {
        public static void WriteLine(string buffer, ConsoleColor foreground = ConsoleColor.DarkGreen, ConsoleColor backgroundColor = ConsoleColor.Black)
        {
            Console.ForegroundColor = foreground;
            Console.BackgroundColor = backgroundColor;
            Console.WriteLine(buffer);
            Console.ResetColor();
        }
    }
}
