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
    /// WinRT implementation of the <see cref="ISymmetricKeyAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class SymmetricKeyAlgorithmProviderFactory : ISymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProviderFactory"/> class.
        /// </summary>
        public SymmetricKeyAlgorithmProviderFactory()
        {
        }

        /// <inheritdoc />
        public ISymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
        {
            return new SymmetricKeyAlgorithmProvider(name, mode, padding);
        }
    }
}
