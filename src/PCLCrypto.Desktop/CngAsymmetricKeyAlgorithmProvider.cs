// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// .NET Framework implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class CngAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="CngAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public CngAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
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
                // Not exposed by CNG. We probably need to switch this to BCrypt.
                KeySizes range;
                switch (this.Algorithm)
                {
                    case AsymmetricAlgorithm.DsaSha1:
                    case AsymmetricAlgorithm.DsaSha256:
                        range = new KeySizes(512, 1024, 64);
                        break;
                    case AsymmetricAlgorithm.EcdsaP256Sha256:
                        range = new KeySizes(256, 256, 0);
                        break;
                    case AsymmetricAlgorithm.EcdsaP384Sha384:
                        range = new KeySizes(384, 384, 0);
                        break;
                    case AsymmetricAlgorithm.EcdsaP521Sha512:
                        range = new KeySizes(521, 521, 0);
                        break;
                    default:
                        throw new NotImplementedException();
                }

                return new[] { range };
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            var keyParameters = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport,
                KeyUsage = CngKeyUsages.AllUsages,
            };
            string keyName = "PclCrypto_" + Guid.NewGuid().ToString();
            CngKey key = CngKey.Create(GetCngAlgorithm(this.algorithm), keyName, keyParameters);
            return new CngCryptographicKey(key, null);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var key = CngKey.Import(keyBlob, GetPlatformKeyBlobType(blobType));
            return new CngCryptographicKey(key, blobType == CryptographicPrivateKeyBlobType.BCryptPrivateKey ? keyBlob : null);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var key = CngKey.Import(keyBlob, GetPlatformKeyBlobType(blobType));
            return new CngCryptographicKey(key, null);
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static CngKeyBlobFormat GetPlatformKeyBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return CngKeyBlobFormat.Pkcs8PrivateBlob;
                case CryptographicPrivateKeyBlobType.BCryptPrivateKey:
                    return CngKeyBlobFormat.GenericPrivateBlob;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static CngKeyBlobFormat GetPlatformKeyBlobType(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.BCryptPublicKey:
                    return CngKeyBlobFormat.GenericPublicBlob;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Returns the platform-specific algorithm to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific algorithm.</returns>
        internal static CngAlgorithm GetCngAlgorithm(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                    return CngAlgorithm.ECDsaP256;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                    return CngAlgorithm.ECDsaP384;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return CngAlgorithm.ECDsaP521;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
