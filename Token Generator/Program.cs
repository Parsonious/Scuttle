// Token Generator/Program.cs
using System.CommandLine;
using Microsoft.Extensions.Options;
using Token_Generator.Services;
using Token_Generator.Models;

class Program
{
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Token Generator CLI Tool");

        var modeOption = new Option<string>(
            "--mode", "Operation mode (encrypt/decrypt)")
        { IsRequired = true };

        var algorithmOption = new Option<string>(
            "--algorithm", "Encryption algorithm to use");

        var encoderOption = new Option<string>(
            "--encoder", "Encoding method to use");

        var titleOption = new Option<string>(
            "--title", "Title for encryption");

        var instructionsOption = new Option<string>(
            "--instructions", "Instructions for encryption");

        var tokenOption = new Option<string>(
            "--token", "Token to decrypt");

        var keyOption = new Option<string>(
            "--key", "Decryption key (Base64)");

        var outputOption = new Option<FileInfo?>(
            "--output", "Output file path");

        var silentOption = new Option<bool>(
            "--silent", "Suppress non-essential output");

        var listAlgorithmsOption = new Option<bool>(
            "--list-algorithms", "List available encryption algorithms");

        var listEncodersOption = new Option<bool>(
            "--list-encoders", "List available encoding methods");

        rootCommand.AddOption(modeOption);
        rootCommand.AddOption(algorithmOption);
        rootCommand.AddOption(encoderOption);
        rootCommand.AddOption(titleOption);
        rootCommand.AddOption(instructionsOption);
        rootCommand.AddOption(tokenOption);
        rootCommand.AddOption(keyOption);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(silentOption);
        rootCommand.AddOption(listAlgorithmsOption);
        rootCommand.AddOption(listEncodersOption);

        rootCommand.SetHandler(async (context) =>
        {
            var options = new CliOptions
            {
                Mode = context.ParseResult.GetValueForOption(modeOption),
                Algorithm = context.ParseResult.GetValueForOption(algorithmOption),
                Encoder = context.ParseResult.GetValueForOption(encoderOption),
                Title = context.ParseResult.GetValueForOption(titleOption),
                Instructions = context.ParseResult.GetValueForOption(instructionsOption),
                Token = context.ParseResult.GetValueForOption(tokenOption),
                Key = context.ParseResult.GetValueForOption(keyOption),
                OutputFile = context.ParseResult.GetValueForOption(outputOption)?.FullName,
                Silent = context.ParseResult.GetValueForOption(silentOption),
                ListAlgorithms = context.ParseResult.GetValueForOption(listAlgorithmsOption),
                ListEncoders = context.ParseResult.GetValueForOption(listEncodersOption)
            };

            var config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            var program = new Program(config);
            await program.RunWithOptionsAsync(options);
        });

        return await rootCommand.InvokeAsync(args);
    }

    private async Task RunWithOptionsAsync(CliOptions options)
    {
        if ( options.ListAlgorithms )
        {
            _displayService.DisplayEncryptionMethods();
            return;
        }

        if ( options.ListEncoders )
        {
            _displayService.DisplayEncodingMethods();
            return;
        }

        switch ( options.Mode?.ToLower() )
        {
            case "encrypt":
                await PerformEncryptionAsync(options);
                break;
            case "decrypt":
                await PerformDecryptionAsync(options);
                break;
            default:
                throw new ArgumentException("Invalid mode specified. Use 'encrypt' or 'decrypt'.");
        }
    }
}
