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
    /// The .NET Framework implementation of the <see cref="IKeyDerivationAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class KeyDerivationAlgorithmProviderFactory : IKeyDerivationAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IKeyDerivationAlgorithmProvider OpenAlgorithm(KeyDerivationAlgorithm algorithm)
        {
            return new KeyDerivationAlgorithmProvider(algorithm);
        }
    }
}
