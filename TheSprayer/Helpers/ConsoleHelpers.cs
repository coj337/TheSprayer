using System;

namespace TheSprayer.Helpers
{
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
