//-----------------------------------------------------------------------
// <copyright file="SymmetricAlgorithmMode.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enum describing symmetric cipher block modes.
    /// </summary>
    public enum SymmetricAlgorithmMode
    {
        /// <summary>
        /// The CBC mode.
        /// </summary>
        Cbc,

        /// <summary>
        /// The ECB mode.
        /// </summary>
        Ecb,

        /// <summary>
        /// The CCM mode.
        /// </summary>
        Ccm,

        /// <summary>
        /// The GCM mode.
        /// </summary>
        Gcm,
    }
}
