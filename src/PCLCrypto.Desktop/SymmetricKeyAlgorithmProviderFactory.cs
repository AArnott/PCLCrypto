//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProviderFactory.cs" company="Andrew Arnott">
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
        public ISymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithm algorithm)
        {
            return new SymmetricKeyAlgorithmProvider(algorithm);
        }
    }
}
