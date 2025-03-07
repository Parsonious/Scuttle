namespace Scuttle.Enums
{
    /// <summary>
    /// Represents different padding schemes used by encryption algorithms
    /// </summary>
    public enum PaddingScheme
    {
        None,           // No padding or handled internally
        PKCS7,          // PKCS#7 padding used by AES, 3DES, etc.
        ISO10126,       // ISO 10126 padding (random with last byte = padding length)
        ZeroPadding,    // Simple zero-padding used by some algorithms
        Custom          // Custom padding for algorithms like ThreeFish
    }
}