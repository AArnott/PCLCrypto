//-----------------------------------------------------------------------
// <copyright file="AsymmetricKeyAlgorithmProviderFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// .NET Framework implementation of the <see cref="IAsymmetricKeyAlgorithmProviderFactory"/> interface.
    /// </summary>
    public class AsymmetricKeyAlgorithmProviderFactory : IAsymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProviderFactory"/> class.
        /// </summary>
        public AsymmetricKeyAlgorithmProviderFactory()
        {
        }

        /// <inheritdoc />
        public IAsymmetricKeyAlgorithmProvider OpenAlgorithm(string algorithm)
        {
            Requires.NotNullOrEmpty(algorithm, "algorithm");
            return new AsymmetricKeyAlgorithmProvider(algorithm);
        }
    }
}
