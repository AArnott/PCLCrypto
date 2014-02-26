//-----------------------------------------------------------------------
// <copyright file="ICryptographicHash.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents a reusable hashing object and contains the result of a hashing
    /// operation.
    /// </summary>
    public interface ICryptographicHash
    {
        /// <summary>
        /// Appends a binary encoded string to the data stored in the CryptographicHash
        /// object.
        /// </summary>
        /// <param name="data">Data to append.</param>
        void Append(byte[] data);

        /// <summary>
        /// Gets hashed data from the CryptographicHash object and resets the object.
        /// </summary>
        /// <returns>Hashed data.</returns>
        byte[] GetValueAndReset();
    }
}
