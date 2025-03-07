using System.Text;
namespace Scuttle.Detection
{
    /// <summary>
    /// File header structure to store encryption metadata
    /// </summary>
    public class EncryptionHeader
    {
        public const int MAGIC_BYTES_LENGTH = 4;
        public const int VERSION_LENGTH = 2;
        public const int ALGORITHM_ID_LENGTH = 4;
        public const int HEADER_SIZE = MAGIC_BYTES_LENGTH + VERSION_LENGTH + ALGORITHM_ID_LENGTH;

        public static readonly byte[] MAGIC_BYTES = Encoding.ASCII.GetBytes("BPIO"); // Scuttle magic bytes
        public const ushort CURRENT_VERSION = 1;

        public ushort Version { get; set; } = CURRENT_VERSION;
        public string AlgorithmId { get; set; } = string.Empty;

        public static EncryptionHeader Read(Stream stream)
        {
            var header = new EncryptionHeader();
            var buffer = new byte[HEADER_SIZE];

            if ( stream.Read(buffer, 0, HEADER_SIZE) != HEADER_SIZE )
                throw new InvalidDataException("Invalid encrypted file format - header too short");

            // Verify magic bytes
            if ( !buffer.Take(MAGIC_BYTES_LENGTH).SequenceEqual(MAGIC_BYTES) )
                throw new InvalidDataException("Not a valid Scuttle encrypted file");

            // Read version
            header.Version = BitConverter.ToUInt16(buffer, MAGIC_BYTES_LENGTH);

            // Read algorithm ID
            header.AlgorithmId = Encoding.ASCII.GetString(buffer, MAGIC_BYTES_LENGTH + VERSION_LENGTH, ALGORITHM_ID_LENGTH).TrimEnd('\0');

            return header;
        }

        public byte[] ToByteArray()
        {
            var buffer = new byte[HEADER_SIZE];

            // Write magic bytes
            Buffer.BlockCopy(MAGIC_BYTES, 0, buffer, 0, MAGIC_BYTES_LENGTH);

            // Write version
            var versionBytes = BitConverter.GetBytes(Version);
            Buffer.BlockCopy(versionBytes, 0, buffer, MAGIC_BYTES_LENGTH, VERSION_LENGTH);

            // Write algorithm ID (padded with zeros if necessary)
            byte[] algIdBytes = new byte[ALGORITHM_ID_LENGTH];
            byte[] inputBytes = Encoding.ASCII.GetBytes(AlgorithmId);
            Buffer.BlockCopy(inputBytes, 0, algIdBytes, 0, Math.Min(inputBytes.Length, ALGORITHM_ID_LENGTH));

            Buffer.BlockCopy(algIdBytes, 0, buffer, MAGIC_BYTES_LENGTH + VERSION_LENGTH, ALGORITHM_ID_LENGTH);

            return buffer;
        }
    }
}