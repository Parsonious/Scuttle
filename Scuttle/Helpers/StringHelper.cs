namespace Scuttle.Helpers
{
    public class StringHelper
    {
        private bool IsHexString(string test)
        {
            // Empty strings are not valid hex strings
            if ( string.IsNullOrEmpty(test) )
                return false;

            // Check if string is a valid hex string
            return test.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        }

        private byte[] ConvertHexStringToByteArray(string hex)
        {
            // Remove any non-hex characters (like spaces or dashes)
            hex = new string(hex.Where(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')).ToArray());

            int numberChars = hex.Length;
            if ( numberChars % 2 != 0 )
            {
                //_logger.LogWarning("Hex string has odd length. Padding with leading zero.");
                hex = "0" + hex; // Pad with leading zero if odd length
                numberChars++;
            }

            byte[] bytes = new byte[numberChars / 2];
            for ( int i = 0; i < numberChars; i += 2 )
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
