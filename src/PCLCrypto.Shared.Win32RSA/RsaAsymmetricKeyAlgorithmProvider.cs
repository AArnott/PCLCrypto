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

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : NCryptAsymmetricKeyProviderBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
            : base(algorithm)
        {
            var algorithmName = algorithm.GetName();
            Requires.Argument(algorithmName == AsymmetricAlgorithmName.Rsa || algorithmName == AsymmetricAlgorithmName.RsaSign, nameof(algorithm), "RSA algorithm expected.");
        }

        /// <inheritdoc />
        protected internal override CryptographicPublicKeyBlobType NativePublicKeyFormatEnum => CryptographicPublicKeyBlobType.BCryptPublicKey;

        /// <inheritdoc />
        protected internal override string NativePublicKeyFormatString => AsymmetricKeyBlobTypes.BCRYPT_RSAPUBLIC_BLOB;

        /// <inheritdoc />
        protected internal override IReadOnlyDictionary<CryptographicPrivateKeyBlobType, string> NativePrivateKeyFormats => new Dictionary<CryptographicPrivateKeyBlobType, string>
        {
            { CryptographicPrivateKeyBlobType.BCryptPrivateKey, AsymmetricKeyBlobTypes.BCRYPT_RSAPRIVATE_BLOB },
            { CryptographicPrivateKeyBlobType.BCryptFullPrivateKey, AsymmetricKeyBlobTypes.BCRYPT_RSAFULLPRIVATE_BLOB },
        };

        /// <inheritdoc />
        protected internal override CryptographicPrivateKeyBlobType PreferredNativePrivateKeyFormat => CryptographicPrivateKeyBlobType.BCryptFullPrivateKey;
    }
}
