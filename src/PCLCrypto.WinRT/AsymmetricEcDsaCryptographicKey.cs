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
    using static PInvoke.BCrypt;

    /// <summary>
    /// A cryptographic key for ECDSA operations.
    /// </summary>
    internal class AsymmetricEcDsaCryptographicKey : BCryptCryptographicKeyBase
    {
        internal AsymmetricEcDsaCryptographicKey(SafeKeyHandle key, AsymmetricAlgorithm algorithm)
        {
            this.Key = key;
        }

        protected override BCrypt.SafeKeyHandle Key { get; }

        protected override string GetBCryptBlobType(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.BCryptPublicKey:
                    return AsymmetricKeyBlobTypes.BCRYPT_ECCPUBLIC_BLOB;
                default:
                    throw new NotSupportedException();
            }
        }

        protected override string GetBCryptBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.BCryptPrivateKey:
                    return AsymmetricKeyBlobTypes.BCRYPT_ECCPRIVATE_BLOB;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
