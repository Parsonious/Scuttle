namespace Scuttle.Encrypt.ChaChaCore
{
    // This class contains all shared constants for ChaCha implementations
    internal static class ChaChaConstants
    {
        // ChaCha state initialization constants - "expand 32-byte k" in ASCII
        public static readonly uint[] StateConstants = {
    0x61707865, // "expa" in little-endian ASCII
    0x3320646E, // "nd 3" in little-endian ASCII
    0x79622D32, // "2-by" in little-endian ASCII
    0x6B206574  // "te k" in little-endian ASCII
};

        public const int KeySize = 32;     // 256 bits
        public const int BlockSize = 64;   // ChaCha20 block size
        public const int TagSize = 16;     // 128 bits for Poly1305

        // Algorithm-specific constants
        public const int ChaCha20NonceSize = 12;  // 96 bits
        public const int XChaCha20NonceSize = 24; // 192 bits for XChaCha20
    }
}
