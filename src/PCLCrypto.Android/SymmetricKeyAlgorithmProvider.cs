//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Java.Security;
    using Javax.Crypto;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="ISymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class SymmetricKeyAlgorithmProvider : ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public SymmetricKeyAlgorithmProvider(SymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public SymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public int BlockLength
        {
            get
            {
                try
                {
                    using (var platform = Cipher.GetInstance(this.algorithm.GetName().GetString()))
                    {
                        return GetBlockSize(this.algorithm, platform);
                    }
                }
                catch (NoSuchAlgorithmException ex)
                {
                    throw new NotSupportedException("Algorithm not supported.", ex);
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            return new SymmetricCryptographicKey(this.Algorithm, keyMaterial);
        }

        /// <summary>
        /// Gets the block size for the specified algorithm.
        /// </summary>
        internal static int GetBlockSize(SymmetricAlgorithm pclAlgorithm, Cipher algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");

            if (algorithm.BlockSize == 0 && pclAlgorithm.GetName() == SymmetricAlgorithmName.Rc4)
            {
                // This is a streaming cipher without a block size. Return 1 to emulate behavior of other platforms.
                return 1;
            }

            return algorithm.BlockSize;
        }
    }
}
