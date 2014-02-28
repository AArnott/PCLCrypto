//-----------------------------------------------------------------------
// <copyright file="CryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Base class for implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal abstract class CryptographicKey
    {
        /// <summary>
        /// Signs data with this key.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The signature.</returns>
        protected internal abstract byte[] Sign(byte[] data);

        /// <summary>
        /// Verifies the signature of data with this key.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid.
        /// </returns>
        protected internal abstract bool VerifySignature(byte[] data, byte[] signature);
    }
}
