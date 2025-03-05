using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Scuttle.Models;

namespace Scuttle.Services
{
    public class ArgumentParser
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ArgumentParser> _logger;

        public ArgumentParser(IConfiguration configuration, ILogger<ArgumentParser> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public CliOptions Parse(string[] args)
        {
            var options = new CliOptions();

            // If no arguments provided, set to interactive mode
            if ( args.Length == 0 )
            {
                options.IsInteractiveMode = true;
                return options;
            }

            // Parse command line arguments
            for ( int i = 0; i < args.Length; i++ )
            {
                switch ( args[i].ToLower() )
                {
                    case "--mode":
                        options.Mode = GetNextArg(args, ref i);
                        break;
                    case "--algorithm":
                        options.Algorithm = GetNextArg(args, ref i);
                        break;
                    case "--encoder":
                        options.Encoder = GetNextArg(args, ref i);
                        break;
                    case "--title":
                        options.Title = GetNextArg(args, ref i);
                        break;
                    case "--instructions":
                        options.Instructions = GetNextArg(args, ref i);
                        break;
                    case "--token":
                        options.Token = GetNextArg(args, ref i);
                        break;
                    case "--key":
                        options.Key = GetNextArg(args, ref i);
                        break;
                    case "--output":
                        options.OutputFile = GetNextArg(args, ref i);
                        break;
                    case "--batch":
                        options.BatchFile = GetNextArg(args, ref i);
                        break;
                    case "--format":
                        options.OutputFormat = GetNextArg(args, ref i);
                        break;
                    case "--silent":
                        options.Silent = true;
                        break;
                    case "--version":
                        options.ShowVersion = true;
                        break;
                    case "--list-algorithms":
                        options.ListAlgorithms = true;
                        break;
                    case "--list-encoders":
                        options.ListEncoders = true;
                        break;
                    default:
                        _logger.LogWarning("Unknown argument: {Arg}", args[i]);
                        break;
                }
            }

            // Apply environment variables and configuration settings
            ApplyEnvironmentVariables(options);
            ApplyConfigurationSettings(options);

            return options;
        }

        private void ApplyEnvironmentVariables(CliOptions options)
        {
            options.Algorithm ??= Environment.GetEnvironmentVariable("TOKEN_ALGORITHM");
            options.Encoder ??= Environment.GetEnvironmentVariable("TOKEN_ENCODER");
            options.OutputFormat ??= Environment.GetEnvironmentVariable("TOKEN_OUTPUT_FORMAT");
            options.LogLevel ??= Environment.GetEnvironmentVariable("TOKEN_LOG_LEVEL");
        }

        private void ApplyConfigurationSettings(CliOptions options)
        {
            var config = _configuration.GetSection("DefaultOptions");
            options.Algorithm ??= config["Algorithm"];
            options.Encoder ??= config["Encoder"];
            options.OutputFormat ??= config["OutputFormat"] ?? "text";
            options.LogLevel ??= config["LogLevel"] ?? "information";
        }

        private string? GetNextArg(string[] args, ref int index)
        {
            if ( index + 1 < args.Length )
            {
                index++;
                return args[index];
            }
            _logger.LogWarning("Missing value for argument: {Arg}", args[index]);
            return null;
        }
    }

}
