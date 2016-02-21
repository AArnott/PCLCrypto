// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
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
        /// A lazy-initialized cache for the <see cref="LegalKeySizes"/> property.
        /// </summary>
        private IReadOnlyList<KeySizes> legalKeySizes;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        public SymmetricKeyAlgorithmProvider(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
        {
            Requires.Argument(mode.IsBlockCipher() == name.IsBlockCipher(), nameof(mode), "Block chaining mode incompatible with cipher. Don't mix streaming and non-streaming ciphers and modes.");
            Requires.Argument(padding == SymmetricAlgorithmPadding.None || mode.IsBlockCipher(), nameof(padding), "Padding does not apply to streaming ciphers.");

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
        public IReadOnlyList<KeySizes> LegalKeySizes
        {
            get
            {
                if (this.legalKeySizes == null)
                {
                    try
                    {
                        // BouncyCastle doesn't offer an API for querying allowed key sizes.
                        // http://stackoverflow.com/q/33974519/46926
                        // So we hard-code them instead.
                        KeySizes result;
                        switch (this.Name)
                        {
                            case SymmetricAlgorithmName.Aes:
                                result = new KeySizes(128, 256, 64);
                                break;
                            case SymmetricAlgorithmName.Des:
                                result = new KeySizes(64, 64, 0);
                                break;
                            case SymmetricAlgorithmName.TripleDes:
                                result = new KeySizes(128, 192, 64);
                                break;
                            case SymmetricAlgorithmName.Rc2:
                                result = new KeySizes(40, 128, 8);
                                break;
                            case SymmetricAlgorithmName.Rc4:
                                result = new KeySizes(8, 512, 8);
                                break;
                            default:
                                throw new NotSupportedException();
                        }

                        this.legalKeySizes = new ReadOnlyCollection<KeySizes>(new[] { result });
                    }
                    catch (NoSuchAlgorithmException ex)
                    {
                        throw new NotSupportedException("Algorithm not supported.", ex);
                    }
                }

                return this.legalKeySizes;
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            return new SymmetricCryptographicKey(this, this.Name, this.Mode, this.Padding, keyMaterial);
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
