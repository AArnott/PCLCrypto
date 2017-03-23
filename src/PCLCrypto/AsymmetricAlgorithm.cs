// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// Asymmetric algorithms supported by some or all platforms.
    /// </summary>
    public enum AsymmetricAlgorithm
    {
        /// <summary>
        /// The DsaSha1 algorithm.
        /// </summary>
        DsaSha1,

        /// <summary>
        /// The DsaSha256 algorithm.
        /// </summary>
        DsaSha256,

        /// <summary>
        /// The EcdsaP256Sha256 algorithm.
        /// </summary>
        EcdsaP256Sha256,

        /// <summary>
        /// The EcdsaP384Sha384 algorithm.
        /// </summary>
        EcdsaP384Sha384,

        /// <summary>
        /// The EcdsaP521Sha512 algorithm.
        /// </summary>
        EcdsaP521Sha512,

        /// <summary>
        /// The RsaOaepSha1 algorithm.
        /// </summary>
        RsaOaepSha1,

        /// <summary>
        /// The RsaOaepSha256 algorithm.
        /// </summary>
        RsaOaepSha256,

        /// <summary>
        /// The RsaOaepSha384 algorithm.
        /// </summary>
        RsaOaepSha384,

        /// <summary>
        /// The RsaOaepSha512 algorithm.
        /// </summary>
        RsaOaepSha512,

        /// <summary>
        /// The RsaPkcs1 algorithm.
        /// </summary>
        RsaPkcs1,

        /// <summary>
        /// The RsaSignPkcs1Sha1 algorithm.
        /// </summary>
        RsaSignPkcs1Sha1,

        /// <summary>
        /// The RsaSignPkcs1Sha256 algorithm.
        /// </summary>
        RsaSignPkcs1Sha256,

        /// <summary>
        /// The RsaSignPkcs1Sha384 algorithm.
        /// </summary>
        RsaSignPkcs1Sha384,

        /// <summary>
        /// The RsaSignPkcs1Sha512 algorithm.
        /// </summary>
        RsaSignPkcs1Sha512,

        /// <summary>
        /// The RsaSignPssSha1 algorithm.
        /// </summary>
        RsaSignPssSha1,

        /// <summary>
        /// The RsaSignPssSha256 algorithm.
        /// </summary>
        RsaSignPssSha256,

        /// <summary>
        /// The RsaSignPssSha384 algorithm.
        /// </summary>
        RsaSignPssSha384,

        /// <summary>
        /// RsaSignPssSha512 algorithm.
        /// </summary>
        RsaSignPssSha512,
    }
}
