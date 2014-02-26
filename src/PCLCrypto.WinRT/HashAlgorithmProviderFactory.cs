//-----------------------------------------------------------------------
// <copyright file="HashAlgorithmProviderFactory.cs" company="Andrew Arnott">
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
    /// A WinRT implementation of <see cref="IHashAlgorithmProviderFactory"/>.
    /// </summary>
    internal class HashAlgorithmProviderFactory : IHashAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IHashAlgorithmProvider OpenAlgorithm(HashAlgorithm algorithm)
        {
            return new HashAlgorithmProvider(algorithm);
        }
    }
}
