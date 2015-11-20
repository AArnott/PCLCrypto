// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// A factory for instances of <see cref="ISymmetricKeyAlgorithmProvider"/>
    /// that serve a specific algorithm.
    /// </summary>
    public interface ISymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Returns a crypto key management for a specified algorithm.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        /// <returns>An instance of <see cref="ISymmetricKeyAlgorithmProvider"/>.</returns>
        ISymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding);
    }
}
