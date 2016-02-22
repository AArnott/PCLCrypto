// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;

    /// <summary>
    /// Extension methods for the <see cref="AsymmetricAlgorithm"/> type.
    /// </summary>
    public static class AsymmetricAlgorithmExtensions
    {
        /// <summary>
        /// Gets the simple name of an asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The name of the algorithm.</returns>
        public static AsymmetricAlgorithmName GetName(this AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.DsaSha256:
                    return AsymmetricAlgorithmName.Dsa;
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return AsymmetricAlgorithmName.Ecdsa;
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaPkcs1:
                    return AsymmetricAlgorithmName.Rsa;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return AsymmetricAlgorithmName.RsaSign;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the padding used for the specified asymmetric signing algorithm.
        /// </summary>
        /// <param name="algorithm">The signing algorithm.</param>
        /// <returns>The signature padding used, if applicable.</returns>
        public static AsymmetricSignaturePadding? GetSignaturePadding(this AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return AsymmetricSignaturePadding.None;

                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return AsymmetricSignaturePadding.Pkcs1;

                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return AsymmetricSignaturePadding.Pss;

                case AsymmetricAlgorithm.RsaPkcs1:
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    // Not a signing algorithm.
                    return null;

                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Gets the padding used for the specified asymmetric encryption algorithm.
        /// </summary>
        /// <param name="algorithm">The encryption algorithm.</param>
        /// <returns>The encryption padding used, if applicable.</returns>
        public static AsymmetricEncryptionPadding? GetEncryptionPadding(this AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.RsaPkcs1:
                    return AsymmetricEncryptionPadding.Pkcs1;

                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    return AsymmetricEncryptionPadding.Oaep;

                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    // not an encryption algorithm.
                    return null;

                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Gets the hash algorithm utilized by the specified asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The asymmetric algorithm.</param>
        /// <returns>The hash algorithm, if applicable.</returns>
        public static HashAlgorithm? GetHashAlgorithm(this AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                    return HashAlgorithm.Sha1;

                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                    return HashAlgorithm.Sha256;

                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                    return HashAlgorithm.Sha384;

                case AsymmetricAlgorithm.EcdsaP521Sha512:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return HashAlgorithm.Sha512;

                case AsymmetricAlgorithm.RsaPkcs1:
                    return null;

                default:
                    throw new NotImplementedException();
            }
        }
    }
}
