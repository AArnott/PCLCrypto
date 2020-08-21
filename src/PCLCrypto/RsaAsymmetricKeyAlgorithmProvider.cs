// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if !(__IOS__ || __ANDROID__)

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using Microsoft;
    using PCLCrypto.Formatters;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of RSA.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public IReadOnlyList<KeySizes> LegalKeySizes
        {
            get
            {
                using (var rsa = Platform.RSA.Create())
                {
                    return (from keySizes in rsa.LegalKeySizes
                            select new KeySizes(keySizes.MinSize, keySizes.MaxSize, keySizes.SkipSize)).ToList();
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            var rsa = new Platform.RSACryptoServiceProvider(keySize);
            return new RsaCryptographicKey(rsa, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, nameof(keyBlob));

            var parameters = KeyFormatter.GetFormatter(blobType)
                .Read(keyBlob)
                .ComputeFullPrivateKeyData();

            if (!CapiKeyFormatter.IsCapiCompatible(parameters))
            {
                // Try to make it CAPI compatible since it's faster on desktop,
                // and the only thing that could possibly work on wp8.
                RSAParameters adjustedParameters = CapiKeyFormatter.NegotiateSizes(parameters);
                if (CapiKeyFormatter.IsCapiCompatible(adjustedParameters))
                {
                    parameters = adjustedParameters;
                }
            }

            Platform.RSA rsa;
            if (CapiKeyFormatter.IsCapiCompatible(parameters))
            {
                rsa = new Platform.RSACryptoServiceProvider();
            }
            else
            {
#if NETFRAMEWORK && false
                rsa = new RSAManaged();
#else
                // Throw the exception explaining the problem.
                CapiKeyFormatter.VerifyCapiCompatibleParameters(parameters);

                // Make it obvious to the compiler that the buck stops here.
                // er... on the line above.
                throw new NotSupportedException();
#endif
            }

            rsa.ImportParameters(KeyFormatter.ToPlatformParameters(parameters));
            return new RsaCryptographicKey(rsa, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, nameof(keyBlob));

            var rsa = new Platform.RSACryptoServiceProvider();
            rsa.ImportParameters(KeyFormatter.ToPlatformParameters(KeyFormatter.GetFormatter(blobType).Read(keyBlob)));
            return new RsaCryptographicKey(rsa, this.algorithm);
        }
    }
}

#endif
