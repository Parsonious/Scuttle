namespace Scuttle.Detection
{
/// <summary>
/// Maps encryption algorithms to file extensions
/// </summary>
public static class AlgorithmExtensionMap
{
    private static readonly Dictionary<string, string> _algorithmToExtension = new()
    {
        { "AESG", ".aes" },     // AES-GCM
        { "CC20", ".c20" },     // ChaCha20
        { "SL20", ".s20" },     // Salsa20
        { "3DES", ".des" },     // Triple DES
        { "3FSH", ".fff" },     // ThreeFish
        { "RC2_", ".rc2" },     // RC2
        { "XCCH", ".cc2" },     // XChaCha
        { "AES_", ".aes" }      // Standard AES
    };

    private static readonly Dictionary<string, string> _extensionToAlgorithm = new();

    static AlgorithmExtensionMap()
    {
        // Initialize the reverse mapping
        foreach ( var pair in _algorithmToExtension )
        {
            var ext = pair.Value.TrimStart('.').ToLowerInvariant();
            _extensionToAlgorithm[ext] = pair.Key;
        }
    }

    public static string GetExtensionForAlgorithm(string algorithmId)
    {
        if ( _algorithmToExtension.TryGetValue(algorithmId, out var extension) )
            return extension;

        return ".enc"; // Default extension
    }

    public static string TryGetAlgorithmFromExtension(string extension)
    {
        extension = extension.TrimStart('.').ToLowerInvariant();

        if ( _extensionToAlgorithm.TryGetValue(extension, out var algorithmId) )
            return algorithmId;

        return string.Empty; // No matching algorithm
    }
}
}