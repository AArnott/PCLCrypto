//-----------------------------------------------------------------------
// <copyright file="CryptographicHashPlain.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of <see cref="CryptographicHash"/>
    /// for use with plain hashing algorithms.
    /// </summary>
    internal class CryptographicHashPlain : NetFxCryptographicHash
    {
        /// <summary>
        /// The algorithm enum.
        /// </summary>
        private HashAlgorithm pclAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicHashPlain" /> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal CryptographicHashPlain(HashAlgorithm algorithm)
        {
            this.pclAlgorithm = algorithm;
        }

        /// <inheritdoc />
        protected override Platform.HashAlgorithm CreateHashAlgorithm()
        {
            return HashAlgorithmProvider.CreateHashAlgorithm(this.pclAlgorithm);
        }
    }
}
