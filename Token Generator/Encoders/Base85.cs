using System;
using System.Collections.Generic;
using System.Text;

namespace Token_Generator.Encoders
{
    internal class Base85
    {
        private const string Base85Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        private static readonly uint[] PowersOf85 = { 52200625, 614125, 7225, 85, 1 };
        private static readonly Dictionary<char, uint> Base85CharMap;

        static Base85()
        {
            Base85CharMap = new Dictionary<char, uint>(85);
            for ( uint i = 0; i < Base85Chars.Length; i++ )
            {
                Base85CharMap[Base85Chars[(int) i]] = i;
            }
        }
        public static void TestBase85()
        {
            byte[] originalData = Encoding.UTF8.GetBytes("Test data for Base85 encoding/decoding.");
            string encodedData = Base85.Encode(originalData);
            byte[] decodedData = Base85.Decode(encodedData);

            if ( originalData.SequenceEqual(decodedData) )
            {
                Console.WriteLine("Base85 encoding/decoding works correctly.");
                Console.WriteLine(Encoding.UTF8.GetString(originalData));
                Console.WriteLine(Encoding.UTF8.GetString(decodedData));
            }
            else
            {
                Console.WriteLine("Base85 encoding/decoding failed.");
            }
        }
        public static string Encode(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return string.Empty;

            // 1. Prepend the original data length (4 bytes, big-endian)
            byte[] lengthBytes = BitConverter.GetBytes(data.Length);
            if ( BitConverter.IsLittleEndian )
                Array.Reverse(lengthBytes);

            List<byte> dataWithLength = new List<byte>();
            dataWithLength.AddRange(lengthBytes);
            dataWithLength.AddRange(data);

            // 2. Use the combined data (length + original data) for encoding
            byte[] paddedData = dataWithLength.ToArray();
            int encodedLength = ((paddedData.Length + 3) / 4) * 5;
            char[] encodedChars = new char[encodedLength];

            uint value = 0;
            int byteCount = 0;
            int charIndex = 0;

            foreach ( byte b in paddedData ) // Use paddedData, not the original data
            {
                value = (value << 8) | b;
                byteCount++;

                if ( byteCount == 4 )
                {
                    for ( int i = 0; i < 5; i++ )
                    {
                        encodedChars[charIndex++] = Base85Chars[(int) ((value / PowersOf85[i]) % 85)];
                    }
                    value = 0;
                    byteCount = 0;
                }
            }

            if ( byteCount > 0 )
            {
                value <<= (4 - byteCount) * 8;
                for ( int i = 0; i < 5; i++ ) // Iterate forward, not backward
                {
                    if ( charIndex < encodedChars.Length )
                    {
                        encodedChars[charIndex++] = Base85Chars[(int) ((value / PowersOf85[i]) % 85)];
                    }
                }
            }

            return new string(encodedChars, 0, charIndex);
        }
        public static byte[] Decode(string text)
        {
            if ( string.IsNullOrEmpty(text) )
                return Array.Empty<byte>();

            // 1. Calculate decoded length to handle partial groups
            int decodedLength = ((text.Length + 4) / 5) * 4;
            byte[] decodedBytes = new byte[decodedLength];

            uint value = 0;
            int charCount = 0;
            int byteIndex = 0;

            foreach ( char c in text )
            {
                if ( !Base85CharMap.TryGetValue(c, out uint digit) )
                    throw new ArgumentException($"Invalid Base85 character: {c}");

                value += digit * PowersOf85[charCount];
                charCount++;

                if ( charCount == 5 )
                {
                    for ( int i = 3; i >= 0; i-- )
                    {
                        decodedBytes[byteIndex++] = (byte) ((value >> (i * 8)) & 0xFF);
                    }
                    value = 0;
                    charCount = 0;
                }
            }

            // 2. Handle partial group (if any)
            if ( charCount > 0 )
            {
                for ( int i = charCount; i < 5; i++ )
                {
                    value += 84 * PowersOf85[i]; // Pad with "z" equivalents
                }
                for ( int i = 3; i >= 0; i-- )
                {
                    if ( byteIndex < decodedBytes.Length )
                    {
                        decodedBytes[byteIndex++] = (byte) ((value >> (i * 8)) & 0xFF);
                    }
                }
            }

            // 3. Resize to actual decoded bytes
            Array.Resize(ref decodedBytes, byteIndex);

            // 4. Extract the original length and truncate padding
            if ( decodedBytes.Length < 4 )
                throw new ArgumentException("Invalid encoded data: Missing length header.");

            byte[] lengthBytes = new byte[4];
            Array.Copy(decodedBytes, 0, lengthBytes, 0, 4);
            if ( BitConverter.IsLittleEndian )
                Array.Reverse(lengthBytes);

            int originalLength = BitConverter.ToInt32(lengthBytes, 0);

            if ( originalLength < 0 || 4 + originalLength > decodedBytes.Length )
                throw new ArgumentException("Invalid encoded data: Corrupted length header.");

            // 5. Copy the original data (excluding the 4-byte length header)
            byte[] result = new byte[originalLength];
            Array.Copy(decodedBytes, 4, result, 0, originalLength);
            return result;
        }
    }
}