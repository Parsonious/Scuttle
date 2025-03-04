namespace Token_Generator.Models
{
    public class CliOptions
    {
        public string? Mode { get; set; }         // "encrypt" or "decrypt"
        public string? Algorithm { get; set; }     // encryption algorithm name
        public string? Encoder { get; set; }       // encoding method
        public string? Title { get; set; }         // for encryption
        public string? Instructions { get; set; }  // for encryption
        public string? Token { get; set; }         // for decryption
        public string? Key { get; set; }           // for decryption
        public string? OutputFile { get; set; }    // save output to file
        public bool Silent { get; set; }           // suppress non-essential output
        public bool ListAlgorithms { get; set; }   // list available algorithms
        public bool ListEncoders { get; set; }     // list available encoders
    }

}
