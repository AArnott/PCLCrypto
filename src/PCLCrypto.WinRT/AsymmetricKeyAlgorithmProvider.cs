// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class AsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The WinRT platform implementation.
        /// </summary>
        private readonly Platform.AsymmetricKeyAlgorithmProvider platform;

        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            this.platform = Platform.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(algorithm));
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
                // Not exposed by WinRT. We probably need to switch this to BCrypt.
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
                        range = new KeySizes(384, 16384, 8);
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

            var key = this.platform.CreateKeyPair((uint)keySize);
            return new WinRTCryptographicKey(key, canExportPrivateKey: true);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var key = this.platform.ImportKeyPair(keyBlob.ToBuffer(), GetPlatformKeyBlobType(blobType));
            return new WinRTCryptographicKey(key, canExportPrivateKey: true);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var key = this.platform.ImportPublicKey(keyBlob.ToBuffer(), GetPlatformKeyBlobType(blobType));
            return new WinRTCryptographicKey(key, canExportPrivateKey: false);
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static Platform.CryptographicPublicKeyBlobType GetPlatformKeyBlobType(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return Platform.CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo;
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    return Platform.CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey;
                case CryptographicPublicKeyBlobType.BCryptPublicKey:
                    return Platform.CryptographicPublicKeyBlobType.BCryptPublicKey;
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                    return Platform.CryptographicPublicKeyBlobType.Capi1PublicKey;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the platform-specific enum value for the given PCL enum value.
        /// </summary>
        /// <param name="blobType">The platform independent enum value for the blob type.</param>
        /// <returns>The platform-specific enum value for the equivalent blob type.</returns>
        internal static Platform.CryptographicPrivateKeyBlobType GetPlatformKeyBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return Platform.CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo;
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return Platform.CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey;
                case CryptographicPrivateKeyBlobType.BCryptPrivateKey:
                    return Platform.CryptographicPrivateKeyBlobType.BCryptPrivateKey;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    return Platform.CryptographicPrivateKeyBlobType.Capi1PrivateKey;
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
                    return Platform.AsymmetricAlgorithmNames.DsaSha1;
                case AsymmetricAlgorithm.DsaSha256:
                    return Platform.AsymmetricAlgorithmNames.DsaSha256;
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP256Sha256;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP384Sha384;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP521Sha512;
                case AsymmetricAlgorithm.RsaOaepSha1:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha1;
                case AsymmetricAlgorithm.RsaOaepSha256:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha256;
                case AsymmetricAlgorithm.RsaOaepSha384:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha384;
                case AsymmetricAlgorithm.RsaOaepSha512:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha512;
                case AsymmetricAlgorithm.RsaPkcs1:
                    return Platform.AsymmetricAlgorithmNames.RsaPkcs1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha256;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha384;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha512;
                case AsymmetricAlgorithm.RsaSignPssSha1:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha1;
                case AsymmetricAlgorithm.RsaSignPssSha256:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha256;
                case AsymmetricAlgorithm.RsaSignPssSha384:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha384;
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
