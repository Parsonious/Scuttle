using Token_Generator.Interfaces;

namespace Token_Generator.Encrypt
{
    internal class EncryptionFactory
    {
        public enum EncryptionType
        {
            AES_GCM,
            ChaCha20,
            XChaCha20,    // Extended nonce ChaCha20
            Threefish,    // High-security block cipher
            ASCON,        // Lightweight AEAD cipher (NIST lightweight finalist)
            Kyber,        // Post-quantum KEM
            // Add more encryption types as needed
        }

        public static IEncryption CreateEncryption(EncryptionType type)
        {
            return type switch
            {
                EncryptionType.AES_GCM => new AesGcmEncrypt(),
                EncryptionType.ChaCha20 => new ChaCha20Encrypt(),
                EncryptionType.XChaCha20 => new XChaCha20Encrypt(),
                EncryptionType.Threefish => new ThreefishEncrypt(),
                _ => throw new ArgumentException("Unsupported encryption type", nameof(type))
            };
        }
    }
}
