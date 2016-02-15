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
            switch (algorithm.GetName())
            {
                case AsymmetricAlgorithmName.Ecdsa:
                    return new ECDsaKeyProvider(algorithm);
                case AsymmetricAlgorithmName.Rsa:
                case AsymmetricAlgorithmName.RsaSign:
                    return new RsaKeyProvider(algorithm);
                case AsymmetricAlgorithmName.Dsa:
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
