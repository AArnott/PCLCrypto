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
                return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var algorithm = this.OpenAlgorithm())
            {
                throw new NotSupportedException();
                ////var key = BCryptImportKeyPair(algorithm, GetPlatformKeyBlobType(blobType), keyBlob, BCryptImportKeyPairFlags.None);
                ////return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            using (var algorithm = this.OpenAlgorithm())
            {
                throw new NotSupportedException();
                ////var key = BCryptImportKeyPair(algorithm, GetPlatformKeyBlobType(blobType, this.Algorithm.GetName()), keyBlob);
                ////return new AsymmetricEcDsaCryptographicKey(key, this.Algorithm);
            }
        }

        private SafeAlgorithmHandle OpenAlgorithm()
        {
            return BCryptOpenAlgorithmProvider(CngUtilities.GetAlgorithmId(this.Algorithm));
        }
    }
}
