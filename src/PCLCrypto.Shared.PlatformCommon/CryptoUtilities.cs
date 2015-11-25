// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
        /// Grows a buffer as necessary to align with a block size.
        /// </summary>
        /// <param name="buffer">The buffer to grow.</param>
        /// <param name="blockLength">The length (in bytes) of a block.</param>
        internal static void ApplyZeroPadding(ref byte[] buffer, int blockLength)
        {
            Requires.NotNull(buffer, nameof(buffer));

            int bytesBeyondLastBlockLength = buffer.Length % blockLength;
            if (bytesBeyondLastBlockLength > 0)
            {
                int growBy = blockLength - bytesBeyondLastBlockLength;
                Array.Resize(ref buffer, buffer.Length + growBy);
            }
        }

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
        /// Creates a copy of a byte array.
        /// </summary>
        /// <param name="buffer">The array to be copied. May be null.</param>
        /// <returns>The copy of the array, or null if <paramref name="buffer"/> was null.</returns>
        internal static byte[] CloneArray(this byte[] buffer)
        {
            if (buffer == null)
            {
                return null;
            }

            var result = new byte[buffer.Length];
            Array.Copy(buffer, result, buffer.Length);
            return result;
        }

        /// <summary>
        /// Disposes a value if it is not null.
        /// </summary>
        /// <param name="value">The value to be disposed of.</param>
        internal static void DisposeIfNotNull(this IDisposable value)
        {
            if (value != null)
            {
                value.Dispose();
            }
        }
    }
}
