using System;
using System.Security.Cryptography;
using System.Text;
using Token_Generator.AES;
using Microsoft.Extensions.Configuration;

class Program
{
    static void Main()
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();


        string secretKey = config["AESSettings:SecretKey"] ?? throw new NullReferenceException("Please provide a valid secret key in the appsettings.json file.");
        string iv = config["AESSettings:IV"] ?? throw new NullReferenceException("Please provide a valid IV in the appsettings.json file.");
        string passphrase = config["AESSettings:Passphrase"] ?? throw new NullReferenceException("Please provide a valid passphrase in the appsettings.json file.");


        Console.WriteLine("Provide the following inputs to generate a token:");
        Console.WriteLine("Title: ");
        string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title), "Article cannot be null.");
        Console.WriteLine("Instructions: ");
        string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions), "Instructions cannot be null.");

        // Convert secretKey to byte array
        byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

        // Encrypt the input strings into a token
        string CBCtoken = CBC.EncryptToken(title, passphrase, instructions, secretKey, iv);
        string GCMtoken = GCM.EncryptToken(title, passphrase, instructions, secretKeyBytes);
        Console.WriteLine("CBC Generated Token: " + CBCtoken);
        Console.WriteLine("GCM Generated Token: " + GCMtoken);

        // Decrypt the token back into the original strings
        string[] decryptedStrings = CBC.DecryptToken(CBCtoken, secretKey, iv);
        Console.WriteLine("Token: " + CBCtoken);
        Console.WriteLine("Decrypted Strings:");
        Console.WriteLine("Title: " + decryptedStrings[0]);
        Console.WriteLine("Passphrase: " + decryptedStrings[1]);
        Console.WriteLine("Instructions: " + decryptedStrings[2]);

        string[] decryptedStringsGCM = GCM.DecryptToken(GCMtoken, secretKeyBytes);
        Console.WriteLine("Token: " + GCMtoken);
        Console.WriteLine("Decrypted Strings:");
        Console.WriteLine("Title: " + decryptedStringsGCM[0]);
        Console.WriteLine("Passphrase: " + decryptedStringsGCM[1]);
        Console.WriteLine("Instructions: " + decryptedStringsGCM[2]);

    }
}
