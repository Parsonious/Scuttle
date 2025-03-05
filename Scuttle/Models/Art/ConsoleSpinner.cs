namespace Scuttle.Models.Art
{
    public class ConsoleSpinner
    {
        private int _counter = 0;
        private readonly string[] _sequence = { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };

        public void Turn(string status = "Processing")
        {
            Console.Write($"\r{status} {_sequence[_counter++ % _sequence.Length]} ");
        }

        public void Stop(string completionMessage = "Done!")
        {
            Console.Write($"\r{new string(' ', Console.WindowWidth - 1)}\r");
            Console.WriteLine(completionMessage);
        }
    }
}
