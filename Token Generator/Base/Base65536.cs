using System;
using System.Collections.Generic;
using System.Text;

namespace Token_Generator.Base
{
    internal class Base65536
    {
        public static string Encode(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return string.Empty;

            StringBuilder sb = new StringBuilder(data.Length / 2 + (data.Length % 2 == 0 ? 0 : 1));

            for ( int i = 0; i < data.Length; i += 2 )
            {
                // Combine two bytes into a 16-bit value
                int value = data[i] << 8;

                // Handle the last byte if the length is odd
                if ( i + 1 < data.Length )
                {
                    value |= data[i + 1];
                }

                // Map the 16-bit value to a code point in the range U+10000 to U+1FFFF
                // Ensure we don't exceed the valid range
                int codePoint = 0x10000 + (value & 0xFFFF);

                // Convert the code point to a UTF-16 encoded string
                sb.Append(char.ConvertFromUtf32(codePoint));
            }

            return sb.ToString();
        }

        public static byte[] Decode(string text)
        {
            if ( string.IsNullOrEmpty(text) )
                return Array.Empty<byte>();

            List<byte> data = new List<byte>();

            for ( int i = 0; i < text.Length; )
            {
                // Get the Unicode code point
                int codePoint = char.ConvertToUtf32(text, i);

                // Move past the surrogate pair if present
                i += char.IsHighSurrogate(text[i]) ? 2 : 1;

                // Validate code point range
                if ( codePoint < 0x10000 || codePoint > 0x1FFFF )
                    throw new ArgumentException($"Invalid character in encoded string at position {i}.");

                // Extract the original 16-bit value
                int value = codePoint - 0x10000;

                // Extract both bytes
                data.Add((byte) (value >> 8));

                // Only add the second byte if we're not at the end of an odd-length sequence
                if ( i < text.Length || (value & 0xFF) != 0 )
                {
                    data.Add((byte) (value & 0xFF));
                }
            }

            return data.ToArray();
        }
    }
}
