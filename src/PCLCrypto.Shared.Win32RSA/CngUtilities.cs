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

    /// <summary>
    /// Crypto utilities for Windows platforms (Cryptography Next Generation).
    /// </summary>
    internal static class CngUtilities
    {
        /// <summary>
        /// Gets the key size that is mandated by certain algorithms.
        /// </summary>
        /// <param name="algorithm">The asymmetric algorithm that mandates a specific key size.</param>
        /// <returns>The key size, in bits.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="algorithm"/> does not mandate a key size.</exception>
        internal static int GetAlgorithmKeySize(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                    return 256;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                    return 384;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return 521;
                default:
                    throw new ArgumentException("algorithm does not specify a key size.");
            }
        }

        /// <summary>
        /// Gets the BCrypt (or NCrypt) algorithm identifier for an asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The PCL asymmetric algorithm.</param>
        /// <returns>The BCrypt/NCrypt compatible algorithm identifier.</returns>
        internal static string GetAlgorithmId(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm.GetName())
            {
                case AsymmetricAlgorithmName.Dsa:
                    return BCrypt.AlgorithmIdentifiers.BCRYPT_DSA_ALGORITHM;
                case AsymmetricAlgorithmName.Ecdsa:
                    switch (GetAlgorithmKeySize(algorithm))
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
