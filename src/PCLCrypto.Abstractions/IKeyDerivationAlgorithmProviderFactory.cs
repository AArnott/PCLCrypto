//-----------------------------------------------------------------------
// <copyright file="IKeyDerivationAlgorithmProviderFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Provides access to key derivation algorithms.
    /// </summary>
    public interface IKeyDerivationAlgorithmProviderFactory
    {
        /// <summary>
        /// Acquires a key derivation algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to obtain.</param>
        /// <returns>An instance of <see cref="IKeyDerivationAlgorithmProvider"/>.</returns>
        IKeyDerivationAlgorithmProvider OpenAlgorithm(KeyDerivationAlgorithm algorithm);
    }
}
