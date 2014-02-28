//-----------------------------------------------------------------------
// <copyright file="KeyDerivationAlgorithmProviderFactory.cs" company="Andrew Arnott">
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

    /// <summary>
    /// The WinRT implementation of the <see cref="IKeyDerivationAlgorithmProviderFactory"/> interface.
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
