namespace Scuttle.Models
{
    public class CliOptions
    {
        public bool IsInteractiveMode { get; set; }
        public string? Mode { get; set; }
        public string? Algorithm { get; set; }
        public string? Encoder { get; set; }
        public string? Title { get; set; }
        public string? Instructions { get; set; }
        public string? Token { get; set; }
        public string? Key { get; set; }
        public string? OutputFile { get; set; }
        public string? BatchFile { get; set; }
        public string? OutputFormat { get; set; } = "text"; // text/json
        public string? LogLevel { get; set; } = "info";
        public bool Silent { get; set; }
        public bool ListAlgorithms { get; set; }
        public bool ListEncoders { get; set; }
        public bool ShowVersion { get; set; }

        public bool Validate(out string error)
        {
            error = string.Empty;

            // Special cases that don't require mode
            if ( ShowVersion || ListAlgorithms || ListEncoders )
                return true;

            // Interactive mode doesn't need validation
            if ( IsInteractiveMode )
                return true;

            // CLI mode validation
            if ( !HasAnyArguments() )
            {
                IsInteractiveMode = true;
                return true;
            }

            if ( string.IsNullOrEmpty(Mode) )
            {
                error = "Mode must be specified (encrypt/decrypt) when using command-line arguments";
                return false;
            }

            switch ( Mode.ToLower() )
            {
                case "encrypt" when !string.IsNullOrEmpty(Algorithm) && (string.IsNullOrEmpty(Title) || string.IsNullOrEmpty(Instructions)):
                    error = "Encryption requires both title and instructions when using command-line arguments";
                    return false;

                case "decrypt" when !string.IsNullOrEmpty(Algorithm) && (string.IsNullOrEmpty(Token) || string.IsNullOrEmpty(Key)):
                    error = "Decryption requires both token and key when using command-line arguments";
                    return false;

                case "encrypt":
                case "decrypt":
                    return true;

                default:
                    error = "Invalid mode specified. Use 'encrypt' or 'decrypt'";
                    return false;
            }
        }

        private bool HasAnyArguments()
        {
            return !string.IsNullOrEmpty(Mode) ||
                   !string.IsNullOrEmpty(Algorithm) ||
                   !string.IsNullOrEmpty(Encoder) ||
                   !string.IsNullOrEmpty(Title) ||
                   !string.IsNullOrEmpty(Instructions) ||
                   !string.IsNullOrEmpty(Token) ||
                   !string.IsNullOrEmpty(Key) ||
                   !string.IsNullOrEmpty(OutputFile) ||
                   !string.IsNullOrEmpty(BatchFile) ||
                   ShowVersion ||
                   ListAlgorithms ||
                   ListEncoders ||
                   Silent;
        }
    }
}
