//-----------------------------------------------------------------------
// <copyright file="IAsymmetricKeyAlgorithmProviderFactory.cs" company="Andrew Arnott">
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
    /// A factory for instances of <see cref="IAsymmetricKeyAlgorithmProvider"/>
    /// that serve a specific algorithm.
    /// </summary>
    public interface IAsymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Returns a crypto key management for a specified algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>An instance of <see cref="IAsymmetricKeyAlgorithmProvider"/>.</returns>
        IAsymmetricKeyAlgorithmProvider OpenAlgorithm(AsymmetricAlgorithm algorithm);
    }
}
