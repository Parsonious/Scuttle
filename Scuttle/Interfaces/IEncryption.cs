using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Interfaces
{
    public interface IEncryption
    {
        byte[] Encrypt(byte[] data, byte[] key);
        byte[] Decrypt(byte[] encryptedData, byte[] key);
        string EncryptAndEncode(string data, byte[] key);
        string DecodeAndDecrypt(string encodedData, byte[] key);
        byte[] GenerateKey();
    }
}
