// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class AsymmetricKeyAlgorithmProviderFactory : IAsymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProviderFactory"/> class.
        /// </summary>
        public AsymmetricKeyAlgorithmProviderFactory()
        {
        }

        /// <inheritdoc />
        public IAsymmetricKeyAlgorithmProvider OpenAlgorithm(AsymmetricAlgorithm algorithm)
        {
            return new AsymmetricKeyAlgorithmProvider(algorithm);
        }
    }
}
