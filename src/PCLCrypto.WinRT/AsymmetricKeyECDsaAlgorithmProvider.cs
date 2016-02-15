// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class AsymmetricKeyECDsaAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        internal const CryptographicPublicKeyBlobType NativePublicKeyFormatEnum = CryptographicPublicKeyBlobType.BCryptPublicKey;
        internal const string NativePublicKeyFormatString = AsymmetricKeyBlobTypes.BCRYPT_ECCPUBLIC_BLOB;
        internal const CryptographicPrivateKeyBlobType NativePrivateKeyFormatEnum = CryptographicPrivateKeyBlobType.BCryptPrivateKey;
        internal const string NativePrivateKeyFormatString = AsymmetricKeyBlobTypes.BCRYPT_ECCPRIVATE_BLOB;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyECDsaAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyECDsaAlgorithmProvider(AsymmetricAlgorithm algorithm)
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
                using (var provider = this.OpenProvider())
                {
                    using (var key = NCryptCreatePersistedKey(provider, CngUtilities.GetAlgorithmId(this.Algorithm)))
                    {
                        var keySizes = NCryptGetProperty<NCRYPT_SUPPORTED_LENGTHS>(key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTHS_PROPERTY);
                        return new KeySizes[]
                        {
                            new KeySizes(keySizes.dwMinLength, keySizes.dwMaxLength, keySizes.dwIncrement),
                        };
                    }
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            using (var provider = this.OpenProvider())
            {
                var key = NCryptCreatePersistedKey(provider, CngUtilities.GetAlgorithmId(this.Algorithm));
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTH_PROPERTY, keySize);
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_EXPORT_POLICY_PROPERTY, 3);
                NCryptFinalizeKey(key).ThrowOnError();
                return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");
            Requires.Argument(blobType == NativePrivateKeyFormatEnum, nameof(blobType), "Unsupported key blob type.");

            try
            {
                using (var provider = this.OpenProvider())
                {
                    var key = NCryptImportKey(
                        provider,
                        SafeKeyHandle.Null,
                        NativePrivateKeyFormatString,
                        IntPtr.Zero,
                        keyBlob);
                    return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
                }
            }
            catch (SecurityStatusException ex)
            {
                if (ex.NativeErrorCode == SECURITY_STATUS.NTE_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");
            Requires.Argument(blobType == NativePublicKeyFormatEnum, nameof(blobType), "Unsupported key blob type.");

            try
            {
                using (var provider = this.OpenProvider())
                {
                    var key = NCryptImportKey(
                        provider,
                        SafeKeyHandle.Null,
                        NativePublicKeyFormatString,
                        IntPtr.Zero,
                        keyBlob);
                    return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
                }
            }
            catch (SecurityStatusException ex)
            {
                if (ex.NativeErrorCode == SECURITY_STATUS.NTE_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        private SafeProviderHandle OpenProvider()
        {
            return NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER);
        }
    }
}
