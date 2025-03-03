using System;
using System.Security.Cryptography;
using System.Text;
using Token_Generator.AES;
using Microsoft.Extensions.Configuration;
using Token_Generator.Encoders;

class Program
{
    /*GCM is more modern and more secure than CBC. It is an authenticated encryption mode with associated data (AEAD) that not only provides confidentiality but also integrity. So we'll use that */
    static void Main()
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        AdaptiveSequential adaSeq = new();
        string secretKey = config["AESSettings:SecretKey"] ?? throw new NullReferenceException("Please provide a valid secret key in the appsettings.json file.");
        string iv = config["AESSettings:IV"] ?? throw new NullReferenceException("Please provide a valid IV in the appsettings.json file.");
        string passphrase = config["AESSettings:Passphrase"] ?? throw new NullReferenceException("Please provide a valid passphrase in the appsettings.json file.");

        Base85.TestBase85();


        Console.WriteLine("Provide the following inputs to generate a token:");
        Console.WriteLine("Title: ");
        string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title), "Article cannot be null.");
        Console.WriteLine("Instructions: ");
        string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions), "Instructions cannot be null.");

        // Convert secretKey to byte array
        byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

        // Encrypt the input strings into a token
        string GCMtoken = Base64.UrlEncode(GCM.EncryptToken(title, passphrase, instructions, secretKeyBytes));
        string GCMB85 = Base85.Encode(GCM.EncryptToken(title, passphrase, instructions, secretKeyBytes));


        string[] decryptedStringsGCM = GCM.DecryptToken(Base64.UrlDecode(GCMtoken), secretKeyBytes);
        Console.WriteLine("Encoded Base 64 Token: " + GCMtoken);
        Console.WriteLine("Decrypted Strings:");
        Console.WriteLine("Title: " + decryptedStringsGCM[0]);
        Console.WriteLine("Passphrase: " + decryptedStringsGCM[1]);
        Console.WriteLine("Instructions: " + decryptedStringsGCM[2]);
        
        string[] decryptedStringsGCMB85 = GCM.DecryptToken(Base85.Decode(GCMB85), secretKeyBytes);
        Console.WriteLine("Encoded Base 85 Token: " + GCMB85);
        Console.WriteLine("Decrypted Strings:");
        Console.WriteLine("Title: " + decryptedStringsGCMB85[0]);
        Console.WriteLine("Passphrase: " + decryptedStringsGCMB85[1]);
        Console.WriteLine("Instructions: " + decryptedStringsGCMB85[2]);

    }
}
