namespace Scuttle.Services;

public class AlgorithmIdentifier
{
    // No dependencies on other services

    public string GetAlgorithmId(string typeName)
    {
        if ( typeName.Contains("AesGcm", StringComparison.OrdinalIgnoreCase) )
            return "AESG";
        else if ( typeName.Contains("ChaCha20", StringComparison.OrdinalIgnoreCase) )
            return "CC20";
        else if ( typeName.Contains("Salsa20", StringComparison.OrdinalIgnoreCase) )
            return "SL20";
        else if ( typeName.Contains("TripleDes", StringComparison.OrdinalIgnoreCase)
                || typeName.Contains("3Des", StringComparison.OrdinalIgnoreCase) )
            return "3DES";
        else if ( typeName.Contains("ThreeFish", StringComparison.OrdinalIgnoreCase) )
            return "3FSH";
        else if ( typeName.Contains("RC2", StringComparison.OrdinalIgnoreCase) )
            return "RC2_";
        else if ( typeName.Contains("XChaCha", StringComparison.OrdinalIgnoreCase) )
            return "XCCH";
        else if ( typeName.Contains("Aes", StringComparison.OrdinalIgnoreCase) )
            return "AES_";

        // Generate a 4-character ID based on the hash of the type name
        var hash = typeName.GetHashCode();
        var bytes = BitConverter.GetBytes(hash);
        return Convert.ToBase64String(bytes).Substring(0, 4)
            .Replace('+', 'P')
            .Replace('/', 'S')
            .Replace('=', 'E');
    }

    public string GetConfigNameFromId(string algorithmId)
    {
        // Direct mapping from algorithm ID to configuration name
        return algorithmId switch
        {
            "AESG" => "aesgcm",
            "CC20" => "chacha20",
            "SL20" => "salsa20",
            "3DES" => "tripledes",
            "3FSH" => "threefish",
            "RC2_" => "rc2",
            "XCCH" => "xchacha",
            "AES_" => "aes",
            _ => algorithmId.ToLowerInvariant()
        };
    }
}
