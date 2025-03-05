namespace Scuttle.Models.Art
{
    public class Util
    {
        public async Task<T> ExecuteWithDelayedSpinner<T>(Func<Task<T>> operation, string spinnerMessage = "Processing", int delayMS = 2000)
        {
            using var cts = new CancellationTokenSource();

            // Start the spinner task with delay
            var spinnerTask = Task.Run(async () =>
            {
                try
                {
                    // Wait before showing the spinner
                    await Task.Delay(delayMS, cts.Token);

                    if ( !cts.Token.IsCancellationRequested )
                    {
                        var spinner = new ConsoleSpinner();
                        while ( !cts.Token.IsCancellationRequested )
                        {
                            spinner.Turn(spinnerMessage);
                            await Task.Delay(100);
                        }
                        spinner.Stop();
                    }
                }
                catch ( OperationCanceledException )
                {
                    // Task was canceled, which is expected
                }
            }, cts.Token);

            try
            {
                // Execute the actual operation
                var result = await operation();

                // Cancel the spinner when operation completes
                cts.Cancel();

                // Simple delay to make sure the spinner stops cleanly
                await Task.Delay(100);

                return result;
            }
            catch ( Exception )
            {
                // Cancel the spinner if operation throws
                cts.Cancel();
                throw;
            }
        }
    }
}
