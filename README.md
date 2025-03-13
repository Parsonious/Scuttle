# Scuttle

**Scuttle** is a .NET 8 console application designed for token-based encryption and decryption. It uses pluggable encoders, supports multiple encryption algorithms, and handles large file operations efficiently.

---

## Features
- **Encryption & Decryption**  
  Command-line options for encrypting and decrypting files, tokens, or text input.
- **Large File Support**  
  Stream-based and memory-mapped approaches for processing large files.
- **Command-Line Interface (CLI)**  
  Supports interactive mode or fully automated usage with CLI arguments.

---

## Getting Started

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
- An environment that can run .NET console apps (e.g., Visual Studio 2022 or the .NET CLI).

### Build & Run
1. **Clone or download** this repository.  
2. **Open** the solution (`Scuttle.sln`) in Visual Studio 2022 **or** navigate to the project folder and run:

### CLI Usage
Run `Scuttle` with command-line options. For example:

You can also specify:
- `--key` or `--key-file` for decryption
- `--output` to define the output file path
- `--silent` to suppress console output
- `--save-key` to store the key in a file

Use `--help` or pass no arguments to enter interactive mode.

---

## Configuration
Scuttle loads configuration from:
- `appsettings.json`
- Environment variables (e.g., `TOKEN_ALGORITHM`, `TOKEN_ENCODER`)
- Command-line parameters  
Configuration determines default encoder, algorithms, and logging options.

---

## Project Structure
- **Services/***: Main logic for handling encryption, file operations, user prompts, and argument parsing.  
- **Models/***: Data models such as `CliOptions` and `BatchOperation`.  
- **Encrypt/***: Encryption strategies for various algorithms.  
- **Program.cs**: Entry point that orchestrates the CLI flow.

---

## Contributing
Feel free to open issues or submit pull requests.
