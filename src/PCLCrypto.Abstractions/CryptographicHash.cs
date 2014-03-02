//-----------------------------------------------------------------------
// <copyright file="CryptographicHash.cs" company="Andrew Arnott">
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
    public abstract class CryptographicHash : IDisposable
    {
        /// <summary>
        /// Appends a binary encoded string to the data stored in the CryptographicHash
        /// object.
        /// </summary>
        /// <param name="data">Data to append.</param>
        public abstract void Append(byte[] data);

        /// <summary>
        /// Gets hashed data from the CryptographicHash object and resets the object.
        /// </summary>
        /// <returns>Hashed data.</returns>
        public abstract byte[] GetValueAndReset();
  
        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
        }
    }
}
