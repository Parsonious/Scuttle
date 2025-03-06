using System.Text;

namespace Scuttle.Services
{
    internal class FileService(DisplayService displayService)
    {
        private readonly DisplayService _displayService = displayService;
        public async Task SaveTokenAsync(string token, string key, string encMethod, string encodeMethod)
        {
            if ( !DisplayService.YesNoPrompt("Would you like to save the token and key to a file?") ) return;

            string? filePath = null;
            bool validPath = false;

            while ( !validPath )
            {
                filePath = GetFilePath();
                if ( string.IsNullOrEmpty(filePath) ) return;

                validPath = await VerifyDirectoryAccessAsync(filePath);
                if ( !validPath )
                {
                    if ( !DisplayService.YesNoPrompt("Would you like to try a different location?") ) return;
                }
            }

            try
            {
                await SaveContentToFileAsync(filePath!, token, key, encMethod, encodeMethod);
            }
            catch ( Exception ex )
            {
                throw new IOException("Failed to save token file.", ex);
            }
        }

        private static async Task<bool> VerifyDirectoryAccessAsync(string filePath)
        {
            try
            {
                string? directory = Path.GetDirectoryName(filePath);
                if ( string.IsNullOrEmpty(directory) ) return false;

                if ( !Directory.Exists(directory) )
                {
                    Directory.CreateDirectory(directory);
                    return true;
                }

                // Test write permissions
                string testFile = Path.Combine(directory, $".test_{Guid.NewGuid()}");
                await File.WriteAllTextAsync(testFile, "");
                File.Delete(testFile);
                return true;
            }
            catch ( Exception ex ) when ( ex is UnauthorizedAccessException || ex is IOException )
            {
                Console.WriteLine($"\nAccess denied: {ex.Message}");
                return false;
            }
        }

        private static string? GetFilePath()
        {
            Console.WriteLine("\nEnter the file path and name (e.g., C:\\Sample\\Directory\\Location\\FileName.txt):");
            Console.WriteLine("Or press Enter to use the current directory.");

            string? input = Console.ReadLine();
            if ( string.IsNullOrWhiteSpace(input) )
            {
                return GenerateDefaultFilePath();
            }

            try
            {
                return Path.GetFullPath(input);
            }
            catch ( Exception )
            {
                Console.WriteLine("Invalid path specified. Using current directory.");
                return GenerateDefaultFilePath();
            }
        }

        private static string GenerateDefaultFilePath()
        {
            string defaultFileName = $"token_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            return Path.Combine(Environment.CurrentDirectory, defaultFileName);
        }

        private static async Task SaveContentToFileAsync(string filePath, string token, string key,
            string encMethod, string encodeMethod)
        {
            var content = GenerateFileContent(token, key, encMethod, encodeMethod);
            await File.WriteAllTextAsync(filePath, content);
            Console.WriteLine($"\nFile saved successfully to: {filePath}");
        }

        private static string GenerateFileContent(string token, string key, string encMethod, string encodeMethod)
        {
            return new StringBuilder()
                .AppendLine("Scuttle Output")
                .AppendLine("--------------------")
                .AppendLine($"Generated: {DateTime.Now}")
                .AppendLine($"Encryption Method: {encMethod}")
                .AppendLine($"Encoding Method: {encodeMethod}")
                .AppendLine("\nTOKEN:")
                .AppendLine(token)
                .AppendLine("\nKEY (Base64):")
                .AppendLine(key)
                .AppendLine("\nNote: Keep this file secure. The key is required to decrypt the token.")
                .ToString();
        }

    }
}
