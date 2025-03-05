using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Token_Generator.Base;

namespace Token_Generator.Encrypt.AES
{
    internal class CBC
    {
        internal static byte[]  EncryptToken(string title, string passphrase, string identifier, string secretKey, string iv)
        {
            // Step 1: Concatenate inputs with a delimiter
            string combined = $"{title};{passphrase};{identifier}";

            // Step 2: Encrypt the combined string using AES
            using ( Aes aes = Aes.Create() )
            {
                aes.Key = Encoding.UTF8.GetBytes(secretKey);
                aes.IV = Encoding.UTF8.GetBytes(iv);

                // Create an encryptor
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                // Encrypt the data
                byte[] encryptedBytes;
                using ( var ms = new MemoryStream() )
                {
                    using ( var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write) )
                    {
                        byte[] plainTextBytes = Encoding.UTF8.GetBytes(combined);
                        cs.Write(plainTextBytes, 0, plainTextBytes.Length);
                    }
                    encryptedBytes = ms.ToArray();
                }

                // Step 3: Convert the encrypted bytes to a URL safe Base64 string (compact token)
                return encryptedBytes;
            }
        }
        internal static string[] DecryptToken(string token, string secretKey, string iv)
        {
            // Step 1: Convert the Base64 token back to bytes
            byte[] encryptedBytes = Base64.UrlDecode(token);

            // Step 2: Decrypt the bytes using AES
            using ( Aes aes = Aes.Create() )
            {
                aes.Key = Encoding.UTF8.GetBytes(secretKey);
                aes.IV = Encoding.UTF8.GetBytes(iv);

                // Create a decryptor
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                // Decrypt the data
                using ( var ms = new MemoryStream(encryptedBytes) )
                {
                    using ( var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read) )
                    {
                        using ( var sr = new StreamReader(cs) )
                        {
                            string decryptedText = sr.ReadToEnd();
                            // Step 3: Split the decrypted string back into the original components
                            return decryptedText.Split(';');
                        }
                    }
                }
            }
        }
    }
}
