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

    internal static class CngUtilities
    {
        internal static string GetAlgorithmId(AsymmetricAlgorithm algorithm, int keySize)
        {
            switch (algorithm.GetName())
            {
                case AsymmetricAlgorithmName.Dsa:
                    return BCrypt.AlgorithmIdentifiers.BCRYPT_DSA_ALGORITHM;
                case AsymmetricAlgorithmName.Ecdsa:
                    switch (keySize)
                    {
                        case 256:
                            return BCrypt.AlgorithmIdentifiers.BCRYPT_ECDSA_P256_ALGORITHM;
                        case 384:
                            return BCrypt.AlgorithmIdentifiers.BCRYPT_ECDSA_P384_ALGORITHM;
                        case 521:
                            return BCrypt.AlgorithmIdentifiers.BCRYPT_ECDSA_P521_ALGORITHM;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }

                case AsymmetricAlgorithmName.Rsa:
                case AsymmetricAlgorithmName.RsaSign:
                    return BCrypt.AlgorithmIdentifiers.BCRYPT_RSA_ALGORITHM;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
