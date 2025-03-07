using Scuttle.Enums;
using Scuttle.Interfaces;

namespace Scuttle.Services
{
    public class PaddingService
    {
        /// <summary>
        /// Determines the padding scheme used by an encryption algorithm
        /// </summary>
        /// <param name="encryption">The encryption algorithm</param>
        /// <returns>The padding scheme used</returns>
        public PaddingScheme DeterminePaddingScheme(IEncryption encryption)
        {
            // Identify the encryption algorithm type and return the appropriate padding scheme
            var encryptionType = encryption.GetType().Name;

            return encryptionType switch
            {
                "AesGcmEncrypt" => PaddingScheme.None,      // AES-GCM doesn't use padding
                "TripleDesEncrypt" => PaddingScheme.PKCS7,  // TripleDES uses PKCS#7
                "RC2Encrypt" => PaddingScheme.PKCS7,        // RC2 uses PKCS#7
                "ChaCha20Encrypt" => PaddingScheme.None,    // Stream cipher, no padding
                "XChaCha20Encrypt" => PaddingScheme.None,   // Stream cipher, no padding
                "Salsa20Encrypt" => PaddingScheme.None,     // Stream cipher, no padding
                "ThreefishEncrypt" => PaddingScheme.Custom, // ThreeFish might use custom padding
                _ => PaddingScheme.None                     // Default to no padding for unknown algorithms
            };
        }

        /// <summary>
        /// Gets the block size for the specified encryption algorithm
        /// </summary>
        /// <param name="encryption">The encryption algorithm</param>
        /// <returns>Block size in bytes</returns>
        public int GetBlockSize(IEncryption encryption)
        {
            // Return the block size based on the encryption algorithm
            var encryptionType = encryption.GetType().Name;

            return encryptionType switch
            {
                "AesGcmEncrypt" => 16,        // AES block size is 128 bits (16 bytes)
                "TripleDesEncrypt" => 8,      // 3DES block size is 64 bits (8 bytes)
                "RC2Encrypt" => 8,            // RC2 block size is 64 bits (8 bytes)
                "ThreefishEncrypt" => 64,     // ThreeFish-512 block size is 512 bits (64 bytes)
                "ChaCha20Encrypt" => 64,      // ChaCha20 doesn't have a traditional block size, but operates on 64-byte blocks
                "XChaCha20Encrypt" => 64,     // XChaCha20 doesn't have a traditional block size, but operates on 64-byte blocks
                "Salsa20Encrypt" => 64,       // Salsa20 doesn't have a traditional block size, but operates on 64-byte blocks
                _ => 16                       // Default to 16 bytes for unknown algorithms
            };
        }

        /// <summary>
        /// Removes padding from the data based on the padding scheme
        /// </summary>
        /// <param name="data">The data with padding</param>
        /// <param name="paddingScheme">The padding scheme used</param>
        /// <returns>The length of the data without padding</returns>
        public int RemovePadding(byte[] data, PaddingScheme paddingScheme)
        {
            if ( data == null || data.Length == 0 )
                return 0;

            return paddingScheme switch
            {
                PaddingScheme.PKCS7 => RemovePKCS7Padding(data),
                PaddingScheme.ISO10126 => RemoveISO10126Padding(data),
                PaddingScheme.ZeroPadding => RemoveZeroPadding(data),
                PaddingScheme.Custom => RemoveCustomPadding(data),
                _ => data.Length // No padding removal
            };
        }

        /// <summary>
        /// Calculates the padding length from the buffer
        /// </summary>
        /// <param name="buffer">The buffer containing the end of the file</param>
        /// <param name="paddingScheme">The padding scheme used</param>
        /// <returns>The length of padding to remove</returns>
        public int CalculatePaddingLength(ReadOnlySpan<byte> buffer, PaddingScheme paddingScheme)
        {
            if ( buffer.IsEmpty )
                return 0;

            return paddingScheme switch
            {
                PaddingScheme.PKCS7 => CalculatePKCS7PaddingLength(buffer),
                PaddingScheme.ISO10126 => CalculateISO10126PaddingLength(buffer),
                PaddingScheme.ZeroPadding => CalculateZeroPaddingLength(buffer),
                PaddingScheme.Custom => CalculateCustomPaddingLength(buffer),
                _ => 0 // No padding
            };
        }

        /// <summary>
        /// Removes PKCS#7 padding from the data
        /// </summary>
        private int RemovePKCS7Padding(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return 0;

            // The last byte indicates the padding length in PKCS#7
            int paddingLength = data[data.Length - 1];

            // Validate padding to ensure it's valid PKCS#7
            if ( paddingLength <= 0 || paddingLength > data.Length )
                return data.Length; // Invalid padding, return original length

            // Verify all padding bytes have the same value
            for ( int i = data.Length - paddingLength; i < data.Length; i++ )
            {
                if ( data[i] != paddingLength )
                    return data.Length; // Invalid padding, return original length
            }

            return data.Length - paddingLength;
        }

        /// <summary>
        /// Calculates PKCS#7 padding length from a buffer
        /// </summary>
        private int CalculatePKCS7PaddingLength(ReadOnlySpan<byte> buffer)
        {
            if ( buffer.IsEmpty )
                return 0;

            // Get the last byte which indicates padding length
            int paddingLength = buffer[buffer.Length - 1];

            // Validate padding
            if ( paddingLength <= 0 || paddingLength > buffer.Length )
                return 0; // Invalid padding

            // Verify all padding bytes have the same value
            for ( int i = buffer.Length - paddingLength; i < buffer.Length; i++ )
            {
                if ( buffer[i] != paddingLength )
                    return 0; // Invalid padding
            }

            return paddingLength;
        }

        /// <summary>
        /// Removes ISO10126 padding from the data
        /// </summary>
        private int RemoveISO10126Padding(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return 0;

            // The last byte indicates the padding length in ISO10126
            int paddingLength = data[data.Length - 1];

            // Validate padding
            if ( paddingLength <= 0 || paddingLength > data.Length )
                return data.Length; // Invalid padding, return original length

            return data.Length - paddingLength;
        }

        /// <summary>
        /// Calculates ISO10126 padding length from a buffer
        /// </summary>
        private int CalculateISO10126PaddingLength(ReadOnlySpan<byte> buffer)
        {
            if ( buffer.IsEmpty )
                return 0;

            // Get the last byte which indicates padding length
            int paddingLength = buffer[buffer.Length - 1];

            // Validate padding
            if ( paddingLength <= 0 || paddingLength > buffer.Length )
                return 0; // Invalid padding

            return paddingLength;
        }

        /// <summary>
        /// Removes zero padding from the data
        /// </summary>
        private int RemoveZeroPadding(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return 0;

            // Find the last non-zero byte
            int i = data.Length - 1;
            while ( i >= 0 && data[i] == 0 )
            {
                i--;
            }

            // Return the length up to and including the last non-zero byte
            return i + 1;
        }

        /// <summary>
        /// Calculates zero padding length from a buffer
        /// </summary>
        private int CalculateZeroPaddingLength(ReadOnlySpan<byte> buffer)
        {
            if ( buffer.IsEmpty )
                return 0;

            // Count trailing zeros
            int count = 0;
            for ( int i = buffer.Length - 1; i >= 0; i-- )
            {
                if ( buffer[i] == 0 )
                    count++;
                else
                    break;
            }

            return count;
        }

        /// <summary>
        /// Handles custom padding schemes used by specific algorithms like ThreeFish
        /// </summary>
        private int RemoveCustomPadding(byte[] data)
        {
            // This would need specific implementation based on the algorithm
            // For now, this is a placeholder that assumes a format where:
            // - The last byte indicates if padding exists (1) or not (0)
            // - If padding exists, the second-to-last byte indicates the padding length

            if ( data == null || data.Length < 2 )
                return data.Length;

            if ( data[data.Length - 1] == 1 ) // Padding indicator
            {
                int paddingLength = data[data.Length - 2];
                if ( paddingLength >= 0 && paddingLength <= data.Length - 2 )
                    return data.Length - paddingLength - 2; // Remove padding and indicators
            }

            return data.Length;
        }

        /// <summary>
        /// Calculates custom padding length from a buffer
        /// </summary>
        private int CalculateCustomPaddingLength(ReadOnlySpan<byte> buffer)
        {
            // Custom algorithm-specific padding detection logic
            // This is a placeholder implementation

            if ( buffer.Length < 2 )
                return 0;

            if ( buffer[buffer.Length - 1] == 1 ) // Padding indicator
            {
                int paddingLength = buffer[buffer.Length - 2];
                if ( paddingLength >= 0 && paddingLength <= buffer.Length - 2 )
                    return paddingLength + 2; // Include padding and indicators
            }

            return 0;
        }
    }
}
