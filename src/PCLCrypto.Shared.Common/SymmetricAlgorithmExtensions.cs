// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using Validation;

    /// <summary>
    /// Extension methods for the <see cref="SymmetricAlgorithm"/> enum and related types.
    /// </summary>
    public static class SymmetricAlgorithmExtensions
    {
        /// <summary>
        /// Gets a value indicating whether the specified algorithm is implemented by a block cipher.
        /// </summary>
        /// <param name="algorithm">The algorithm to check.</param>
        /// <returns><c>true</c> if the cipher is a block cipher; <c>false</c> otherwise.</returns>
        public static bool IsBlockCipher(this SymmetricAlgorithm algorithm)
        {
            return algorithm.GetMode() != SymmetricAlgorithmMode.Streaming;
        }

        /// <summary>
        /// Gets a value indicating whether the specified algorithm is implemented by a block cipher.
        /// </summary>
        /// <param name="algorithm">The algorithm to check.</param>
        /// <returns><c>true</c> if the cipher is a block cipher; <c>false</c> otherwise.</returns>
        public static bool IsBlockCipher(this SymmetricAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithmName.Aes:
                case SymmetricAlgorithmName.Des:
                case SymmetricAlgorithmName.TripleDes:
                case SymmetricAlgorithmName.Rc2:
                    return true;
                case SymmetricAlgorithmName.Rc4:
                    return false;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets a value indicating whether the specified mode is implemented by a block cipher.
        /// </summary>
        /// <param name="mode">The mode to check.</param>
        /// <returns><c>true</c> if the cipher is a block cipher; <c>false</c> otherwise.</returns>
        public static bool IsBlockCipher(this SymmetricAlgorithmMode mode) => mode != SymmetricAlgorithmMode.Streaming;

        /// <summary>
        /// Gets a value indicating whether the specified mode offers authentication.
        /// </summary>
        /// <param name="mode">The mode to check.</param>
        /// <returns><c>true</c> if the cipher is an authenticating block mode cipher; <c>false</c> otherwise.</returns>
        public static bool IsAuthenticated(this SymmetricAlgorithmMode mode)
            => mode == SymmetricAlgorithmMode.Gcm || mode == SymmetricAlgorithmMode.Ccm;

        /// <summary>
        /// Returns a platform-specific algorithm that conforms to the prescribed platform-neutral algorithm.
        /// </summary>
        /// <param name="algorithm">The PCL algorithm.</param>
        /// <returns>
        /// The platform-specific algorithm.
        /// </returns>
        public static SymmetricAlgorithmName GetName(this SymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesCcm:
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.AesGcm:
                    return SymmetricAlgorithmName.Aes;
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                    return SymmetricAlgorithmName.Des;
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    return SymmetricAlgorithmName.Rc2;
                case SymmetricAlgorithm.Rc4:
                    return SymmetricAlgorithmName.Rc4;
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    return SymmetricAlgorithmName.TripleDes;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets the block mode for an algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The block mode.</returns>
        public static SymmetricAlgorithmMode GetMode(this SymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                    return SymmetricAlgorithmMode.Cbc;
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    return SymmetricAlgorithmMode.Ecb;
                case SymmetricAlgorithm.AesCcm:
                    return SymmetricAlgorithmMode.Ccm;
                case SymmetricAlgorithm.AesGcm:
                    return SymmetricAlgorithmMode.Gcm;
                case SymmetricAlgorithm.Rc4:
                    return SymmetricAlgorithmMode.Streaming;
                default:
                    throw Assumes.NotReachable();
            }
        }

        /// <summary>
        /// Gets the padding.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The padding.</returns>
        public static SymmetricAlgorithmPadding GetPadding(this SymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.AesCcm:
                case SymmetricAlgorithm.AesGcm:
                case SymmetricAlgorithm.Rc4:
                    return SymmetricAlgorithmPadding.None;
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    return SymmetricAlgorithmPadding.PKCS7;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Finds a composite <see cref="SymmetricAlgorithm"/> for the specified unit parts, if one exists.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        /// <param name="algorithm">Receives the composite algorithm enum value, if one exists.</param>
        /// <returns><c>true</c> if a match was found; otherwise <c>false</c>.</returns>
        public static bool TryAssemblyAlgorithm(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding, out SymmetricAlgorithm algorithm)
        {
            foreach (SymmetricAlgorithm assembled in Enum.GetValues(typeof(SymmetricAlgorithm)))
            {
                if (assembled.GetName() == name && assembled.GetMode() == mode && assembled.GetPadding() == padding)
                {
                    algorithm = assembled;
                    return true;
                }
            }

            algorithm = (SymmetricAlgorithm)0;
            return false;
        }

        /// <summary>
        /// Gets a value indicating whether the specified block mode requires an initialization vector.
        /// </summary>
        /// <param name="mode">The block mode to check.</param>
        /// <returns><c>true</c> if the block mode uses an initialization vector; <c>false</c> otherwise.</returns>
        public static bool UsesIV(this SymmetricAlgorithmMode mode)
        {
            switch (mode)
            {
                case SymmetricAlgorithmMode.Cbc:
                case SymmetricAlgorithmMode.Ccm:
                case SymmetricAlgorithmMode.Gcm:
                    return true;
                case SymmetricAlgorithmMode.Ecb:
                    return false;
                case SymmetricAlgorithmMode.Streaming:
                    return false;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets a value indicating whether the specified algorithm requires an initialization vector.
        /// </summary>
        /// <param name="algorithm">The algorithm to check.</param>
        /// <returns><c>true</c> if the block mode uses an initialization vector; <c>false</c> otherwise.</returns>
        public static bool UsesIV(this SymmetricAlgorithm algorithm) => UsesIV(algorithm.GetMode());

        /// <summary>
        /// Gets the string representation of an algorithm name.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string, such as "AES".</returns>
        public static string GetString(this SymmetricAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithmName.Aes:
                    return "AES";
                case SymmetricAlgorithmName.Des:
                    return "DES";
                case SymmetricAlgorithmName.Rc2:
                    return "RC2";
                case SymmetricAlgorithmName.Rc4:
                    return "RC4";
                case SymmetricAlgorithmName.TripleDes:
                    return "TRIPLEDES";
                default:
                    throw new ArgumentException();
            }
        }
    }
}
