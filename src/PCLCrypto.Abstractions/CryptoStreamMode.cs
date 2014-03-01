//-----------------------------------------------------------------------
// <copyright file="CryptoStreamMode.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    /// <summary>
    /// Specifies the mode of a cryptographic stream.
    /// </summary>
    public enum CryptoStreamMode
    {
        /// <summary>
        /// Read access to a cryptographic stream.
        /// </summary>
        Read,

        /// <summary>
        /// Write access to a cryptographic stream.
        /// </summary>
        Write,
    }
}
