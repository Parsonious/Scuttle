namespace Scuttle.Encrypt.Strategies.AesGcm
{
    /// <summary>
    /// Base abstract strategy for AES-GCM implementations that provides common functionality
    /// </summary>
    internal abstract class BaseAesGcmStrategy : IAesGcmStrategy
    {
        // Constants
        protected const int KeySize = 32;    // 256 bits
        protected const int NonceSize = 12;  // 96 bits for GCM
        protected const int TagSize = 16;    // 128 bits for Authentication Tag

        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Encrypts data using AES-GCM
        /// </summary>
        public abstract byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with AES-GCM
        /// </summary>
        public abstract byte[] Decrypt(byte[] encryptedData, byte[] key);

        /// <summary>
        /// Parallel encryption for large data sets, falls back to regular encryption if not overridden
        /// </summary>
        public virtual byte[] EncryptParallel(byte[] data, byte[] key)
        {
            return Encrypt(data, key);
        }

        /// <summary>
        /// Parallel decryption for large data sets, falls back to regular decryption if not overridden
        /// </summary>
        public virtual byte[] DecryptParallel(byte[] encryptedData, byte[] key)
        {
            return Decrypt(encryptedData, key);
        }

        /// <summary>
        /// Validates input parameters for encryption methods
        /// </summary>
        protected static void ValidateInputs(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));
        }

        /// <summary>
        /// Constant-time comparison of two byte spans to prevent timing attacks
        /// </summary>
        protected static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if ( a.Length != b.Length )
                return false;

            int result = 0;
            for ( int i = 0; i < a.Length; i++ )
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }
    }
}
