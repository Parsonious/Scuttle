using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Models.Art
{
    public static class Graphic
    {
        public static void DisplayGraphicAndVersion(string version)
        {
            DisplayGraphic();
            Console.WriteLine($"\nScuttle v{version}");
            Console.WriteLine("Secure Token Generation and Decryption Tool");
        }
        public static void DisplayGraphic()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"   _____           _   _   _      ");
            Console.WriteLine(@"  / ____|         | | | | | |     ");
            Console.WriteLine(@" | (___   ___ _   _| |_| |_| | ___ ");
            Console.WriteLine(@"  \___ \ / __| | | | __| __| |/ _ \");
            Console.WriteLine(@"  ____) | (__| |_| | |_| |_| |  __/");
            Console.WriteLine(@" |_____/ \___|\__,_|\__|\__|_|\___|");
            Console.ResetColor();
        }

    }
}
