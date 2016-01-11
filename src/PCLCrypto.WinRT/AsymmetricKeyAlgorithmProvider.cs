// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using static PInvoke.BCrypt;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class AsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        public AsymmetricAlgorithm Algorithm { get; }

        /// <inheritdoc/>
        public IReadOnlyList<KeySizes> LegalKeySizes
        {
            get
            {
                using (var algorithm = this.OpenAlgorithm())
                {
                    var keySizes = BCryptGetProperty<BCRYPT_KEY_LENGTHS_STRUCT>(algorithm, PropertyNames.BCRYPT_KEY_LENGTHS);
                    return new KeySizes[]
                    {
                        new KeySizes(keySizes.MinLength, keySizes.MaxLength, keySizes.Increment),
                    };
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            using (var algorithm = this.OpenAlgorithm())
            {
                var key = BCryptGenerateKeyPair(algorithm, keySize);
                BCryptFinalizeKeyPair(key).ThrowOnError();
                return new AsymmetricCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var algorithm = this.OpenAlgorithm())
            {
                var key = BCryptImportKeyPair(algorithm, GetPlatformKeyBlobType(blobType), keyBlob, BCryptImportKeyPairFlags.None);
                return new AsymmetricCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var algorithm = this.OpenAlgorithm())
            {
                var key = BCryptImportKeyPair(algorithm, GetPlatformKeyBlobType(blobType, this.Algorithm.GetName()), keyBlob);
                return new AsymmetricCryptographicKey(key, this.Algorithm);
            }
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static string GetPlatformKeyBlobType(CryptographicPublicKeyBlobType blobType, AsymmetricAlgorithmName algorithmName)
        {
            switch (algorithmName)
            {
                case AsymmetricAlgorithmName.Rsa:
                case AsymmetricAlgorithmName.RsaSign:
                    switch (blobType)
                    {
                        // TODO: fix these
                        case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                            return AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;
                        case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                            return AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;
                        case CryptographicPublicKeyBlobType.BCryptPublicKey:
                            return AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;
                        case CryptographicPublicKeyBlobType.Capi1PublicKey:
                            return AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;
                        default:
                            throw new NotSupportedException();
                    }

                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static string GetPlatformKeyBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                // TODO: fix these
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return AsymmetricKeyBlobTypes.BCRYPT_PRIVATE_KEY_BLOB;
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return AsymmetricKeyBlobTypes.BCRYPT_PRIVATE_KEY_BLOB;
                case CryptographicPrivateKeyBlobType.BCryptPrivateKey:
                    return AsymmetricKeyBlobTypes.BCRYPT_PRIVATE_KEY_BLOB;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    return AsymmetricKeyBlobTypes.BCRYPT_PRIVATE_KEY_BLOB;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.DsaSha256:
                    return AlgorithmIdentifiers.BCRYPT_DSA_ALGORITHM;
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                    return AlgorithmIdentifiers.BCRYPT_ECDSA_P256_ALGORITHM;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                    return AlgorithmIdentifiers.BCRYPT_ECDSA_P384_ALGORITHM;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return AlgorithmIdentifiers.BCRYPT_ECDSA_P521_ALGORITHM;
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaPkcs1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return AlgorithmIdentifiers.BCRYPT_RSA_ALGORITHM;
                default:
                    throw new NotSupportedException();
            }
        }

        private SafeAlgorithmHandle OpenAlgorithm()
        {
            return BCryptOpenAlgorithmProvider(GetAlgorithmName(this.Algorithm));
        }
    }
}
