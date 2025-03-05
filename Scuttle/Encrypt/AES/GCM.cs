using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Scuttle.Encoders;

namespace Scuttle.Encrypt.AES
{
    internal class GCM
    {
        internal static byte[] EncryptToken(string title, string passphrase, string identifier, byte[] key)
        {
            // Step 1: Concatenate inputs with a delimiter
            string combined = $"{title};{passphrase};{identifier}";
            byte[] plaintext = Encoding.UTF8.GetBytes(combined);

            using ( var compressedStream = new MemoryStream() )
            {
                using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Compress) )
                {
                    gzipStream.Write(plaintext, 0, plaintext.Length);
                }
                plaintext = compressedStream.ToArray();
            }

            // Step 2: Generate a random nonce (12 bytes for AES-GCM)
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            // Step 3: Encrypt the data using AES-GCM
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16]; // Authentication tag
            using ( var aesGcm = new AesGcm(key, tag.Length) )
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            // Step 4: Combine nonce, ciphertext, and tag into a single token
            byte[] encryptedToken = new byte[nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, encryptedToken, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, encryptedToken, nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, encryptedToken, nonce.Length + ciphertext.Length, tag.Length);

            return encryptedToken;
        }
        internal static string[] DecryptToken(byte[] encryptedBytes, byte[] key)
        {
            // Extract nonce, ciphertext, and tag from the token
            byte[] nonce = new byte[12];
            byte[] ciphertext = new byte[encryptedBytes.Length - nonce.Length - 16];
            byte[] tag = new byte[16];
            Buffer.BlockCopy(encryptedBytes, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(encryptedBytes, nonce.Length, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encryptedBytes, nonce.Length + ciphertext.Length, tag, 0, tag.Length);

            // Step 2: Decrypt the data using AES-GCM
            byte[] plaintext = new byte[ciphertext.Length];
            using ( var aesGcm = new AesGcm(key, tag.Length) )
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            using (var compressedStream = new MemoryStream(plaintext) )
            {
                using (var decompressedStream = new MemoryStream() )
                {
                    using ( var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress) )
                    {
                        gzipStream.CopyTo(decompressedStream);
                    }
                    plaintext = decompressedStream.ToArray();
                }
            }
            // Step 3: Split the decrypted string back into the original components
            string combined = Encoding.UTF8.GetString(plaintext);
            return combined.Split(';');
        }
    }
}
