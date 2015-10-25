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
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>An instance of <see cref="ISymmetricKeyAlgorithmProvider"/>.</returns>
        ISymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithm algorithm);
    }
}
