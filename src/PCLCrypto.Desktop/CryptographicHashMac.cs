//-----------------------------------------------------------------------
// <copyright file="CryptographicHashMac.cs" company="Andrew Arnott">
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
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicHash"/>
    /// for use with MAC algorithms.
    /// </summary>
    internal class CryptographicHashMac : CryptographicHash
    {
        /// <summary>
        /// The algorithm enum.
        /// </summary>
        private readonly MacAlgorithm pclAlgorithm;

        /// <summary>
        /// The key to use in producing a MAC instead of an ordinary hash.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicHashMac"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="key">The key.</param>
        internal CryptographicHashMac(MacAlgorithm algorithm, byte[] key)
        {
            Requires.NotNull(key, "key");

            this.pclAlgorithm = algorithm;
            this.key = key;
        }

        /// <inheritdoc />
        protected override Platform.HashAlgorithm CreateHashAlgorithm()
        {
            var algorithm = MacAlgorithmProvider.GetAlgorithm(this.pclAlgorithm);
            algorithm.Key = this.key;
            return algorithm;
        }
    }
}
