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
    using Validation;
    using Platform = System.Security.Cryptography;

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
                using (var platform = GetAlgorithm(this.algorithm))
                {
                    return platform.BlockSize / 8;
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

#if Android
            return new SymmetricCryptographicKey(this.Algorithm, keyMaterial);
#else
            var platform = GetAlgorithm(this.algorithm);
            try
            {
                platform.Key = keyMaterial;
            }
            catch (Platform.CryptographicException ex)
            {
#if SILVERLIGHT
                throw new ArgumentException(ex.Message, ex);
#else
                throw new ArgumentException(ex.Message, "keyMaterial", ex);
#endif
            }

            return new SymmetricCryptographicKey(platform);
#endif
        }

#if !SILVERLIGHT
        /// <summary>
        /// Gets the platform enum value for the block mode used by the specified algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The platform-specific enum value describing the block mode.</returns>
        private static Platform.CipherMode GetMode(SymmetricAlgorithm algorithm)
        {
            switch (SymmetricKeyAlgorithmProviderFactory.GetMode(algorithm))
            {
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmMode.Cbc:
                    return Platform.CipherMode.CBC;
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmMode.Ecb:
                    return Platform.CipherMode.ECB;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the platform enum value for the padding used by the specified algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The platform-specific enum value for the padding.</returns>
        private static Platform.PaddingMode GetPadding(SymmetricAlgorithm algorithm)
        {
            switch (SymmetricKeyAlgorithmProviderFactory.GetPadding(algorithm))
            {
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmPadding.None:
                    return Platform.PaddingMode.None;
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmPadding.PKCS7:
                    return Platform.PaddingMode.PKCS7;
                default:
                    throw new ArgumentException();
            }
        }
#endif

        /// <summary>
        /// Returns a platform-specific algorithm that conforms to the prescribed platform-neutral algorithm.
        /// </summary>
        /// <param name="algorithm">The PCL algorithm.</param>
        /// <returns>
        /// The platform-specific algorithm.
        /// </returns>
        private static Platform.SymmetricAlgorithm GetAlgorithm(SymmetricAlgorithm algorithm)
        {
#if SILVERLIGHT || __IOS__
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbcPkcs7:
                    return new Platform.AesManaged();
                default:
                    throw new NotSupportedException();
            }
#else
            Platform.SymmetricAlgorithm platform = Platform.SymmetricAlgorithm.Create(
                SymmetricKeyAlgorithmProviderFactory.GetTitleName(algorithm));
            if (platform == null)
            {
                throw new NotSupportedException();
            }

            platform.Mode = GetMode(algorithm);
            platform.Padding = GetPadding(algorithm);

            return platform;
#endif
        }
    }
}
