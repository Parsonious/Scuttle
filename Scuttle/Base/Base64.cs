namespace Scuttle.Base
{
    internal class Base64
    {
        public static string UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }
        public static byte[] UrlDecode(string token)
        {
            return Convert.FromBase64String(token.Replace('-', '+')
                .Replace('_', '/') + new string('=', (4 - token.Length % 4) % 4));
        }
    }
}
