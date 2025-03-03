using System;
using System.Collections.Generic;
using System.Text;

namespace Token_Generator.Encoders
{
    internal class Base65536
    {
        public static string Encode(byte[] data)
        {
            if ( data == null || data.Length == 0 )
                return string.Empty;

            StringBuilder sb = new StringBuilder((data.Length + 1) / 2);

            for ( int i = 0; i < data.Length; i += 2 )
            {
                // Combine two bytes into a 16-bit value
                ushort value = data[i];
                value <<= 8;

                if ( i + 1 < data.Length )
                {
                    value |= data[i + 1];
                }

                // Map the 16-bit value to a code point in the range U+10000 to U+1FFFF
                int codePoint = 0x10000 + value;

                // Convert the code point to a UTF-16 encoded string
                sb.Append(char.ConvertFromUtf32(codePoint));
            }

            return sb.ToString();
        }

        public static byte[] Decode(string text)
        {
            if ( string.IsNullOrEmpty(text) )
                return Array.Empty<byte>();

            List<byte> data = new List<byte>(text.Length * 2);

            int i = 0;
            while ( i < text.Length )
            {
                int codePoint = char.ConvertToUtf32(text, i);

                // Move to the next character or surrogate pair
                i += char.IsHighSurrogate(text, i) ? 2 : 1;

                // Reverse the mapping to get the original 16-bit value
                if ( codePoint < 0x10000 || codePoint > 0x1FFFF )
                    throw new ArgumentException("Invalid character in encoded string.");

                ushort value = (ushort) (codePoint - 0x10000);

                // Split the 16-bit value back into two bytes
                byte highByte = (byte) (value >> 8);
                byte lowByte = (byte) (value & 0xFF);

                data.Add(highByte);
                if ( i <= text.Length * 2 ) // Avoid adding an extra byte from padding
                {
                    data.Add(lowByte);
                }
            }

            // Remove potential padding zero byte
            if ( data.Count > 0 && data[^1] == 0 )
                data.RemoveAt(data.Count - 1);

            return data.ToArray();
        }
    }
}
