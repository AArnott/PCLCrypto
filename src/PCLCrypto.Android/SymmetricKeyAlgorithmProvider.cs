// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
    internal partial class SymmetricKeyAlgorithmProvider : ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        public SymmetricKeyAlgorithmProvider(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
        {
            this.Name = name;
            this.Mode = mode;
            this.Padding = padding;
        }

        /// <inheritdoc/>
        public int BlockLength
        {
            get
            {
                try
                {
                    using (var platform = Cipher.GetInstance(this.Name.GetString()))
                    {
                        return GetBlockSize(this.Mode, platform);
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

            return new SymmetricCryptographicKey(this.Name, this.Mode, this.Padding, keyMaterial);
        }

        /// <summary>
        /// Gets the block size (in bytes) for the specified algorithm.
        /// </summary>
        /// <param name="mode">The algorithm mode.</param>
        /// <param name="algorithm">The platform-specific algorithm.</param>
        /// <returns>The block size (in bytes).</returns>
        internal static int GetBlockSize(SymmetricAlgorithmMode mode, Cipher algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");

            if (algorithm.BlockSize == 0 && mode == SymmetricAlgorithmMode.Streaming)
            {
                // This is a streaming cipher without a block size. Return 1 to emulate behavior of other platforms.
                return 1;
            }

            return algorithm.BlockSize;
        }
    }
}
