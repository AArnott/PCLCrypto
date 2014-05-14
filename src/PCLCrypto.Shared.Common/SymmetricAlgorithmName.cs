//-----------------------------------------------------------------------
// <copyright file="SymmetricAlgorithmName.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enum describing symmetric algorithms.
    /// </summary>
    public enum SymmetricAlgorithmName
    {
        /// <summary>
        /// The AES algorithm.
        /// </summary>
        Aes,

        /// <summary>
        /// The DES algorithm.
        /// </summary>
        Des,

        /// <summary>
        /// The TRIPLEDES algorithm.
        /// </summary>
        TripleDes,

        /// <summary>
        /// The RC2 algorithm.
        /// </summary>
        Rc2,

        /// <summary>
        /// The RC4 algorithm.
        /// </summary>
        Rc4,
    }
}
