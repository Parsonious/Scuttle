using System.Text.Json;

namespace Token_Generator.Services
{
    public class OutputFormatter
    {
        public string Format(object data, string format)
        {
            return format.ToLower() switch
            {
                "json" => JsonSerializer.Serialize(data, new JsonSerializerOptions
                {
                    WriteIndented = true
                }),
                _ => data.ToString() ?? string.Empty
            };
        }
    }
}
