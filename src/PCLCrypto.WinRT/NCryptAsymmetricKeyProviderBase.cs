// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Formatters;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    internal abstract class NCryptAsymmetricKeyProviderBase : IAsymmetricKeyAlgorithmProvider
    {
        protected NCryptAsymmetricKeyProviderBase(AsymmetricAlgorithm algorithm)
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
                using (var provider = NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER))
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

        protected internal abstract CryptographicPublicKeyBlobType NativePublicKeyFormatEnum { get; }

        protected internal abstract string NativePublicKeyFormatString { get; }

        protected internal abstract IReadOnlyDictionary<CryptographicPrivateKeyBlobType, string> NativePrivateKeyFormats { get; }

        protected internal abstract CryptographicPrivateKeyBlobType PreferredNativePrivateKeyFormat { get; }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            using (var provider = NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER))
            {
                var key = NCryptCreatePersistedKey(provider, CngUtilities.GetAlgorithmId(this.Algorithm));
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTH_PROPERTY, keySize);
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_EXPORT_POLICY_PROPERTY, 3);
                NCryptFinalizeKey(key).ThrowOnError();
                return this.CreateKey(key, publicKeyOnly: false);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var provider = NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER))
            {
                byte[] bcryptPrivateBlob;
                string nativeFormatString;
                if (NativePrivateKeyFormats.TryGetValue(blobType, out nativeFormatString))
                {
                    bcryptPrivateBlob = keyBlob;
                }
                else
                {
                    var parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
                    bcryptPrivateBlob = KeyFormatter.GetFormatter(PreferredNativePrivateKeyFormat).Write(parameters);
                    nativeFormatString = NativePrivateKeyFormats[PreferredNativePrivateKeyFormat];
                }

                var key = NCryptImportKey(provider, null, nativeFormatString, IntPtr.Zero, bcryptPrivateBlob);
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_EXPORT_POLICY_PROPERTY, 3);
                return this.CreateKey(key, publicKeyOnly: false);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var provider = NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER))
            {
                byte[] bcryptPublicBlob = blobType == NativePublicKeyFormatEnum
                    ? keyBlob
                    : KeyFormatter.GetFormatter(NativePublicKeyFormatEnum).Write(KeyFormatter.GetFormatter(blobType).Read(keyBlob));
                var key = NCryptImportKey(provider, null, NativePublicKeyFormatString, IntPtr.Zero, bcryptPublicBlob);
                return this.CreateKey(key, publicKeyOnly: true);
            }
        }

        protected abstract ICryptographicKey CreateKey(SafeKeyHandle key, bool publicKeyOnly);
    }
}
