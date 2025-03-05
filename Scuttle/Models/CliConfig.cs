namespace Token_Generator.Models
{
    public class CliConfig
    {
        public string DefaultAlgorithm { get; set; } = "ChaCha20";
        public string DefaultEncoder { get; set; } = "Base64";
        public string DefaultOutputPath { get; set; } = "./output";
        public bool EnableLogging { get; set; } = true;
        public string LogLevel { get; set; } = "Information";
        public string LogPath { get; set; } = "logs";
        public bool EnableBatchProcessing { get; set; } = false;
        public int BatchSize { get; set; } = 100;
    }
}
