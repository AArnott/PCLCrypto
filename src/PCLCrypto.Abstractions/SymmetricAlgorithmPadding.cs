//-----------------------------------------------------------------------
// <copyright file="SymmetricAlgorithmPadding.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enumeration describing cipher block padding options.
    /// </summary>
    public enum SymmetricAlgorithmPadding
    {
        /// <summary>
        /// Use no padding at all.
        /// </summary>
        None,

        /// <summary>
        /// Use PKCS7 padding.
        /// </summary>
        PKCS7,
    }
}
