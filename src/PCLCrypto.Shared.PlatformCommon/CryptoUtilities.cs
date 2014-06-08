//-----------------------------------------------------------------------
// <copyright file="CryptoUtilities.cs" company="Andrew Arnott">
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
    using Validation;

    /// <summary>
    /// An assortment of crypto utilities.
    /// </summary>
    internal static class CryptoUtilities
    {
        /// <summary>
        /// Performs a constant time comparison between two buffers.
        /// </summary>
        /// <param name="buffer1">The first buffer.</param>
        /// <param name="buffer2">The second buffer.</param>
        /// <returns><c>true</c> if the buffers have exactly the same contents; <c>false</c> otherwise.</returns>
        internal static bool BufferEquals(byte[] buffer1, byte[] buffer2)
        {
            Requires.NotNull(buffer1, "buffer1");
            Requires.NotNull(buffer2, "buffer2");

            if (buffer1.Length != buffer2.Length)
            {
                return false;
            }

            // SECURITY NOTE: Do *not* fast path out of the loop once a mismatch is found.
            // That opens the door to timing security exploits. We must do all the work
            // no matter where a deviation may be.
            bool mismatchFound = false;
            for (int i = 0; i < buffer1.Length; i++)
            {
                mismatchFound |= buffer1[i] != buffer2[i];
            }

            return !mismatchFound;
        }

        /// <summary>
        /// Disposes a value if it is not null.
        /// </summary>
        internal static void DisposeIfNotNull(this IDisposable value)
        {
            if (value != null)
            {
                value.Dispose();
            }
        }
    }
}
