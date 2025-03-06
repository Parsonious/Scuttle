namespace Scuttle.Encrypt.Strategies.RC2
{
    /// <summary>
    /// Base abstract strategy for RC2 implementations that provides common functionality
    /// </summary>
    internal abstract class BaseRC2Strategy : IRC2Strategy
    {
        // Constants
        protected const int KeySize = 16;    // 128 bits
        protected const int IVSize = 8;      // 64 bits

        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Encrypts data using RC2
        /// </summary>
        public abstract byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with RC2
        /// </summary>
        public abstract byte[] Decrypt(byte[] encryptedData, byte[] key);

        /// <summary>
        /// Validates input parameters for encryption methods
        /// </summary>
        protected static void ValidateInputs(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        }
    }
}
