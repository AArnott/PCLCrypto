// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// The shared implementation of the <see cref="IMacAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class MacAlgorithmProviderFactory : IMacAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IMacAlgorithmProvider OpenAlgorithm(MacAlgorithm algorithm)
        {
            return new MacAlgorithmProvider(algorithm);
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        internal static string GetAlgorithmName(MacAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case MacAlgorithm.AesCmac:
                    return "AesCmac";
                case MacAlgorithm.HmacMd5:
                    return "HmacMd5";
                case MacAlgorithm.HmacSha1:
                    return "HmacSha1";
                case MacAlgorithm.HmacSha256:
                    return "HmacSha256";
                case MacAlgorithm.HmacSha384:
                    return "HmacSha384";
                case MacAlgorithm.HmacSha512:
                    return "HmacSha512";
                default:
                    throw new ArgumentException();
            }
        }
    }
}