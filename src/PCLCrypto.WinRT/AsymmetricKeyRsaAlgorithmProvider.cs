// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Formatters;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class AsymmetricKeyRsaAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        internal const CryptographicPublicKeyBlobType NativePublicKeyFormatEnum = CryptographicPublicKeyBlobType.BCryptPublicKey;
        internal const string NativePublicKeyFormatString = AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;
        internal static readonly IReadOnlyDictionary<CryptographicPrivateKeyBlobType, string> NativePrivateKeyFormats = new Dictionary<CryptographicPrivateKeyBlobType, string>
        {
            { CryptographicPrivateKeyBlobType.BCryptPrivateKey, AsymmetricKeyBlobTypes.BCRYPT_RSAPRIVATE_BLOB },
            { CryptographicPrivateKeyBlobType.BCryptFullPrivateKey, AsymmetricKeyBlobTypes.BCRYPT_RSAFULLPRIVATE_BLOB },
        };
        internal const CryptographicPrivateKeyBlobType PreferredNativePrivateKeyFormat = CryptographicPrivateKeyBlobType.BCryptFullPrivateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyRsaAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyRsaAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            var algorithmName = algorithm.GetName();
            Requires.Argument(algorithmName == AsymmetricAlgorithmName.Rsa || algorithmName == AsymmetricAlgorithmName.RsaSign, nameof(algorithm), "RSA algorithm expected.");

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
                    using (var key = NCryptCreatePersistedKey(provider, CngUtilities.GetAlgorithmId(this.Algorithm, 0)))
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
                var key = NCryptCreatePersistedKey(provider, CngUtilities.GetAlgorithmId(this.Algorithm, keySize));
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTH_PROPERTY, keySize);
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_EXPORT_POLICY_PROPERTY, 3);
                NCryptFinalizeKey(key).ThrowOnError();
                return new AsymmetricRsaCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var provider = this.OpenProvider())
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
                return new AsymmetricRsaCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var provider = this.OpenProvider())
            {
                byte[] bcryptPublicBlob = blobType == NativePublicKeyFormatEnum
                    ? keyBlob
                    : KeyFormatter.GetFormatter(NativePublicKeyFormatEnum).Write(KeyFormatter.GetFormatter(blobType).Read(keyBlob));
                var key = NCryptImportKey(provider, null, NativePublicKeyFormatString, IntPtr.Zero, bcryptPublicBlob);
                return new AsymmetricRsaCryptographicKey(key, this.Algorithm);
            }
        }

        private SafeProviderHandle OpenProvider()
        {
            return NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER);
        }
    }
}
