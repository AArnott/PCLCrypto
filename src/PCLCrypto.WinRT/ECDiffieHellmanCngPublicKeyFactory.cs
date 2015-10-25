// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using static PInvoke.BCrypt;

    /// <summary>
    /// The WinRT implementation of <see cref="IECDiffieHellmanCngPublicKeyFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanCngPublicKeyFactory : IECDiffieHellmanCngPublicKeyFactory
    {
        /// <inheritdoc />
        public IECDiffieHellmanPublicKey FromByteArray(byte[] publicKey)
        {
            SafeAlgorithmHandle algorithm;
            var keyBlob = new EccKeyBlob(publicKey);
            switch (keyBlob.Magic)
            {
                case EccKeyBlobMagicNumbers.BCRYPT_ECDH_PUBLIC_P256_MAGIC:
                    algorithm = ECDiffieHellmanFactory.BCryptOpenAlgorithmProvider(256);
                    break;
                case EccKeyBlobMagicNumbers.BCRYPT_ECDH_PUBLIC_P384_MAGIC:
                    algorithm = ECDiffieHellmanFactory.BCryptOpenAlgorithmProvider(384);
                    break;
                case EccKeyBlobMagicNumbers.BCRYPT_ECDH_PUBLIC_P521_MAGIC:
                    algorithm = ECDiffieHellmanFactory.BCryptOpenAlgorithmProvider(521);
                    break;
                default:
                    throw new ArgumentException("Unexpected type of key blob.");
            }

            SafeKeyHandle keyHandle;
            keyHandle = BCryptImportKeyPair(
                algorithm,
                AsymmetricKeyBlobTypes.EccPublic,
                publicKey,
                BCryptImportKeyPairFlags.None);
            algorithm.Dispose();

            return new ECDiffieHellmanPublicKey(keyHandle);
        }
    }
}
