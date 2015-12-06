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
    using Validation;
    using Platform = System.Security.Cryptography;

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
                using (var platform = this.GetAlgorithm())
                {
                    return platform.BlockSize / 8;
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
                    using (var platform = this.GetAlgorithm())
                    {
                        this.legalKeySizes = new ReadOnlyCollection<KeySizes>(
                            (from ks in platform.LegalKeySizes
                             select new KeySizes(ks.MinSize, ks.MaxSize, ks.SkipSize)).ToList());
                    }
                }

                return this.legalKeySizes;
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            var platform = this.GetAlgorithm();
            try
            {
                platform.Key = keyMaterial;
            }
            catch (Platform.CryptographicException ex)
            {
#if SILVERLIGHT
                throw new ArgumentException(ex.Message, ex);
#else
                throw new ArgumentException(ex.Message, nameof(keyMaterial), ex);
#endif
            }

            return new SymmetricCryptographicKey(platform, this.Name, this.Mode, this.Padding);
        }

        /// <summary>
        /// Disposes resources associated with this instance.
        /// </summary>
        public void Dispose()
        {
        }

#if !SILVERLIGHT
        /// <summary>
        /// Gets the platform enum value for the block mode used by the specified algorithm.
        /// </summary>
        /// <param name="mode">The algorithm mode.</param>
        /// <returns>The platform-specific enum value describing the block mode.</returns>
        private static Platform.CipherMode GetMode(SymmetricAlgorithmMode mode)
        {
            switch (mode)
            {
                case SymmetricAlgorithmMode.Cbc:
                    return Platform.CipherMode.CBC;
                case SymmetricAlgorithmMode.Ecb:
                    return Platform.CipherMode.ECB;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the platform enum value for the padding used by the specified algorithm.
        /// </summary>
        /// <param name="padding">The algorithm padding.</param>
        /// <returns>The platform-specific enum value for the padding.</returns>
        private static Platform.PaddingMode GetPadding(SymmetricAlgorithmPadding padding)
        {
            switch (padding)
            {
                case SymmetricAlgorithmPadding.None:
                    return Platform.PaddingMode.None;
                case SymmetricAlgorithmPadding.PKCS7:
                    return Platform.PaddingMode.PKCS7;
                case SymmetricAlgorithmPadding.Zeros:
                    return Platform.PaddingMode.Zeros;
                default:
                    throw new ArgumentException();
            }
        }
#endif

        /// <summary>
        /// Returns a platform-specific algorithm that conforms to the prescribed platform-neutral algorithm.
        /// </summary>
        /// <returns>
        /// The platform-specific algorithm.
        /// </returns>
        private Platform.SymmetricAlgorithm GetAlgorithm()
        {
#if SILVERLIGHT
            if (this.Name == SymmetricAlgorithmName.Aes &&
                this.Mode == SymmetricAlgorithmMode.Cbc &&
                this.Padding == SymmetricAlgorithmPadding.PKCS7)
            {
                return new Platform.AesManaged();
            }
            else
            {
                throw new NotSupportedException();
            }
#else
            Platform.SymmetricAlgorithm platform = null;
#if __IOS__
            if (this.Name == SymmetricAlgorithmName.Aes)
            {
                platform = new Platform.AesManaged();
            }
#else
            platform = Platform.SymmetricAlgorithm.Create(this.Name.GetString());
#endif
            if (platform == null)
            {
                throw new NotSupportedException();
            }

            platform.Mode = GetMode(this.Mode);
            platform.Padding = GetPadding(this.Padding);

            return platform;
#endif
        }
    }
}
