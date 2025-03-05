using Microsoft.Extensions.Logging;

namespace Scuttle.Encrypt.Strategies.RC2
{
    /// <summary>
    /// Factory that selects the optimal RC2 implementation
    /// </summary>
    internal static class RC2StrategyFactory
    {
        private static IRC2Strategy? _cachedStrategy;
        private static readonly object _lock = new();

        /// <summary>
        /// Gets the best available implementation
        /// </summary>
        public static IRC2Strategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<IRC2Strategy>();

                // Add the standard implementation as a fallback
                strategies.Add(new RC2StandardStrategy());
                logger?.LogDebug("Standard RC2 implementation is available");

                // Add enhanced implementation if appropriate
                strategies.Add(new RC2EnhancedStrategy());
                logger?.LogDebug("Enhanced RC2 implementation is available");

                // Select the strategy with the highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected RC2 implementation: {Description}",
                    _cachedStrategy.Description);

                return _cachedStrategy;
            }
        }

        /// <summary>
        /// Forces the use of a specific implementation type
        /// </summary>
        /// <remarks>
        /// This is primarily useful for testing or in specific scenarios where you want
        /// to bypass the automatic selection.
        /// </remarks>
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : IRC2Strategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced RC2 implementation to: {Description}",
                    _cachedStrategy.Description);
            }
        }

        /// <summary>
        /// Clears the cached strategy, allowing it to be re-selected on next use
        /// </summary>
        internal static void ResetStrategy()
        {
            lock ( _lock )
            {
                _cachedStrategy = null;
            }
        }
    }
}
