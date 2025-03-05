using Microsoft.Extensions.Logging;
using Scuttle.Encrypt.Strategies.XChaCha20;
using System.Runtime.Versioning;

namespace Scuttle.Factories
{
    /// <summary>
    /// Factory that selects the optimal XChaCha20 implementation for the current hardware
    /// </summary>
    internal static class XChaCha20StrategyFactory
    {
        private static IXChaCha20Strategy? _cachedStrategy;
        private static readonly object _lock = new();

        /// <summary>
        /// Gets the best available implementation for the current platform
        /// </summary>
        public static IXChaCha20Strategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<IXChaCha20Strategy>();

                // Always add the scalar fallback strategy since it works on all platforms
                strategies.Add(new XChaCha20ScalarStrategy());
                logger?.LogDebug("Scalar XChaCha20 implementation is available");

                // Try platform-specific implementations with proper OS checks
                if ( IsWindowsOrLinuxOrMacOS() )
                {
                    // The IsSupported check is also necessary in addition to the OS check
                    // because the OS might be supported but the CPU might not have the instruction set

#if NET7_0_OR_GREATER
                    // Check for AVX2 support (highest priority, needs both OS and CPU support)
                    if ( TryIsAvx2Supported() )
                    {
                        strategies.Add(new XChaCha20Avx2Strategy());
                        logger?.LogDebug("AVX2 XChaCha20 implementation is available");
                    }

                    // Check for SSE2 support (medium priority)
                    if ( TryIsSse2Supported() )
                    {
                        strategies.Add(new XChaCha20Sse2Strategy());
                        logger?.LogDebug("SSE2 XChaCha20 implementation is available");
                    }

                    // Check for ARM NEON support (medium priority)
                    if ( TryIsAdvSimdSupported() )
                    {
                        strategies.Add(new XChaCha20AdvSimdStrategy());
                        logger?.LogDebug("ARM NEON XChaCha20 implementation is available");
                    }
#endif
                }

                // Select the strategy with the highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected XChaCha20 implementation: {Description}",
                    _cachedStrategy.Description);

                return _cachedStrategy;
            }
        }

        /// <summary>
        /// Forces the use of a specific implementation type, ignoring hardware support
        /// </summary>
        /// <remarks>
        /// This is primarily useful for testing or in specific scenarios where you want
        /// to bypass the automatic selection.
        /// </remarks>
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : IXChaCha20Strategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced XChaCha20 implementation to: {Description}",
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
                // If we get an exception, the platform doesn't support AVX2
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
                // If we get an exception, the platform doesn't support SSE2
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
                // If we get an exception, the platform doesn't support ARM Advanced SIMD
                return false;
            }
        }
    }
}
