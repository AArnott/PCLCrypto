// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// Constructs instances of <see cref="IHashAlgorithmProvider"/>.
    /// </summary>
    public interface IHashAlgorithmProviderFactory
    {
        /// <summary>
        /// Returns an instance of <see cref="IHashAlgorithmProvider"/>
        /// configured for a specific algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>The hash algorithm provider.</returns>
        IHashAlgorithmProvider OpenAlgorithm(HashAlgorithm algorithm);
    }
}
