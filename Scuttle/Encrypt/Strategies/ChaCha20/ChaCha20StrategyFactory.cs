using Microsoft.Extensions.Logging;
using Scuttle.Encrypt.Strategies.XChaCha20;
using System.Runtime.Versioning;

namespace Scuttle.Encrypt.Strategies.ChaCha20
{
    /// <summary>
    /// Factory that selects the optimal ChaCha20 implementation for the current hardware
    /// </summary>
    internal static class ChaCha20StrategyFactory
    {
        private static IChaCha20Strategy? _cachedStrategy;
        private static readonly object _lock = new();

        /// <summary>
        /// Gets the best available implementation for the current platform
        /// </summary>
        public static IChaCha20Strategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<IChaCha20Strategy>();

                // Always add the scalar fallback strategy since it works on all platforms
                strategies.Add(new ChaCha20ScalarStrategy());
                logger?.LogDebug("Scalar ChaCha20 implementation is available");

                // Try platform-specific implementations with proper OS checks
                if ( IsWindowsOrLinuxOrMacOS() )
                {
#if NET7_0_OR_GREATER
                    // Check for AVX2 support (highest priority, needs both OS and CPU support)
                    if ( TryIsAvx2Supported() )
                    {
                        strategies.Add(new ChaCha20Avx2Strategy());
                        logger?.LogDebug("AVX2 ChaCha20 implementation is available");
                    }

                    // Check for SSE2 support (medium priority)
                    if ( TryIsSse2Supported() )
                    {
                        strategies.Add(new ChaCha20Sse2Strategy());
                        logger?.LogDebug("SSE2 ChaCha20 implementation is available");
                    }

                    // Check for ARM NEON support (medium priority)
                    if ( TryIsAdvSimdSupported() )
                    {
                        strategies.Add(new ChaCha20AdvSimdStrategy());
                        logger?.LogDebug("ARM NEON ChaCha20 implementation is available");
                    }
#endif
                }

                // Select the strategy with the highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected ChaCha20 implementation: {Description}",
                    _cachedStrategy.Description);

                return _cachedStrategy;
            }
        }

        /// <summary>
        /// Forces the use of a specific implementation type, ignoring hardware support
        /// </summary>
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : IChaCha20Strategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced ChaCha20 implementation to: {Description}",
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

        /// <summary>
        /// Safely checks if the current OS is Windows, Linux or macOS
        /// </summary>
        private static bool IsWindowsOrLinuxOrMacOS()
        {
            return OperatingSystem.IsWindows() ||
                   OperatingSystem.IsLinux() ||
                   OperatingSystem.IsMacOS();
        }

        /// <summary>
        /// Safely checks AVX2 support
        /// </summary>
        [SupportedOSPlatform("windows")]
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        private static bool TryIsAvx2Supported()
        {
            try
            {
                return System.Runtime.Intrinsics.X86.Avx2.IsSupported;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Safely checks SSE2 support
        /// </summary>
        [SupportedOSPlatform("windows")]
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        private static bool TryIsSse2Supported()
        {
            try
            {
                return System.Runtime.Intrinsics.X86.Sse2.IsSupported;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Safely checks ARM Advanced SIMD support
        /// </summary>
        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        [SupportedOSPlatform("windows")]
        private static bool TryIsAdvSimdSupported()
        {
            try
            {
                return System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported;
            }
            catch
            {
                return false;
            }
        }
    }
}
