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

    /// <summary>
    /// A base class for NCrypt-based asymmetric keys.
    /// </summary>
    internal abstract class NCryptAsymmetricKeyProviderBase : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NCryptAsymmetricKeyProviderBase"/> class.
        /// </summary>
        /// <param name="algorithm">The asymmetric algorithm.</param>
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

        /// <summary>
        /// Gets the PCL blob type that identifies the preferred public key format for NCrypt.
        /// This should be the PCL equivalent of <see cref="NativePublicKeyFormatString"/>.
        /// </summary>
        protected internal abstract CryptographicPublicKeyBlobType NativePublicKeyFormatEnum { get; }

        /// <summary>
        /// Gets the NCrypt string that identifies the preferred format for serialized public keys.
        /// </summary>
        protected internal abstract string NativePublicKeyFormatString { get; }

        /// <summary>
        /// Gets a map of private key blob types to their NCrypt key format names.
        /// </summary>
        protected internal abstract IReadOnlyDictionary<CryptographicPrivateKeyBlobType, string> NativePrivateKeyFormats { get; }

        /// <summary>
        /// Gets the NCrypt string that identifies the preferred format for serialized private keys.
        /// </summary>
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
                return this.CreateKey(key, isPublicOnly: false);
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
                if (this.NativePrivateKeyFormats.TryGetValue(blobType, out nativeFormatString))
                {
                    bcryptPrivateBlob = keyBlob;
                }
                else
                {
                    var parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
                    bcryptPrivateBlob = KeyFormatter.GetFormatter(this.PreferredNativePrivateKeyFormat).Write(parameters);
                    nativeFormatString = this.NativePrivateKeyFormats[this.PreferredNativePrivateKeyFormat];
                }

                var key = NCryptImportKey(provider, null, nativeFormatString, IntPtr.Zero, bcryptPrivateBlob);
                NCryptSetProperty(key, KeyStoragePropertyIdentifiers.NCRYPT_EXPORT_POLICY_PROPERTY, 3);
                return this.CreateKey(key, isPublicOnly: false);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var provider = NCryptOpenStorageProvider(KeyStorageProviders.MS_KEY_STORAGE_PROVIDER))
            {
                byte[] bcryptPublicBlob = blobType == this.NativePublicKeyFormatEnum
                    ? keyBlob
                    : KeyFormatter.GetFormatter(this.NativePublicKeyFormatEnum).Write(KeyFormatter.GetFormatter(blobType).Read(keyBlob));
                var key = NCryptImportKey(provider, null, this.NativePublicKeyFormatString, IntPtr.Zero, bcryptPublicBlob);
                return this.CreateKey(key, isPublicOnly: true);
            }
        }

        /// <summary>
        /// Instantiates an instance of <see cref="ICryptographicKey"/>
        /// (usually a derivative of <see cref="NCryptAsymmetricKey"/>).
        /// </summary>
        /// <param name="key">The native key to wrap.</param>
        /// <param name="isPublicOnly"><c>true</c> if the <paramref name="key"/> contains only the public key.</param>
        /// <returns>The instantiated PCL wrapper.</returns>
        protected virtual ICryptographicKey CreateKey(SafeKeyHandle key, bool isPublicOnly)
        {
            return new NCryptAsymmetricKey(this, key, isPublicOnly);
        }
    }
}
