// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// Symmetric algorithms supported by some or all platforms.
    /// </summary>
    public enum SymmetricAlgorithm
    {
        /// <summary>
        /// The AesCbc algorithm.
        /// </summary>
        AesCbc,

        /// <summary>
        /// The AesCbcPkcs7 algorithm.
        /// </summary>
        AesCbcPkcs7,

        /// <summary>
        /// The AesCcm algorithm.
        /// </summary>
        AesCcm,

        /// <summary>
        /// The AesEcb algorithm.
        /// </summary>
        AesEcb,

        /// <summary>
        /// The AesEcbPkcs7 algorithm.
        /// </summary>
        AesEcbPkcs7,

        /// <summary>
        /// The AesGcm algorithm.
        /// </summary>
        AesGcm,

        /// <summary>
        /// The DesCbc algorithm.
        /// </summary>
        DesCbc,

        /// <summary>
        /// The DesCbcPkcs7 algorithm.
        /// </summary>
        DesCbcPkcs7,

        /// <summary>
        /// The DesEcb algorithm.
        /// </summary>
        DesEcb,

        /// <summary>
        /// The DesEcbPkcs7 algorithm.
        /// </summary>
        DesEcbPkcs7,

        /// <summary>
        /// The Rc2Cbc algorithm.
        /// </summary>
        Rc2Cbc,

        /// <summary>
        /// The Rc2CbcPkcs7 algorithm.
        /// </summary>
        Rc2CbcPkcs7,

        /// <summary>
        /// The Rc2Ecb algorithm.
        /// </summary>
        Rc2Ecb,

        /// <summary>
        /// The Rc2EcbPkcs7 algorithm.
        /// </summary>
        Rc2EcbPkcs7,

        /// <summary>
        /// The Rc4 algorithm.
        /// </summary>
        Rc4,

        /// <summary>
        /// The TripleDesCbc algorithm.
        /// </summary>
        TripleDesCbc,

        /// <summary>
        /// The TripleDesCbcPkcs7 algorithm.
        /// </summary>
        TripleDesCbcPkcs7,

        /// <summary>
        /// The TripleDesEcb algorithm.
        /// </summary>
        TripleDesEcb,

        /// <summary>
        /// The TripleDesEcbPkcs7 algorithm.
        /// </summary>
        TripleDesEcbPkcs7,
    }
}
