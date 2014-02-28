//-----------------------------------------------------------------------
// <copyright file="WinRTUtilities.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using Validation;
    using Windows.Storage.Streams;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// Utilities common to an IronPigeon application targeting WinRT.
    /// </summary>
    internal static class WinRTUtilities
    {
        /// <summary>
        /// An empty buffer.
        /// </summary>
        private static readonly byte[] EmptyBuffer = new byte[0];

        /// <summary>
        /// Converts a WinRT buffer to a .NET buffer.
        /// </summary>
        /// <param name="buffer">The WinRT buffer.</param>
        /// <returns>The .NET buffer.</returns>
        public static byte[] ToArray(this IBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (buffer.Length == 0)
            {
                return EmptyBuffer; // CopyToByteArray produces a null array in this case, so we fix it here.
            }

            byte[] result;
            Platform.CryptographicBuffer.CopyToByteArray(buffer, out result);
            return result;
        }

        /// <summary>
        /// Converts a .NET buffer to a WinRT buffer.
        /// </summary>
        /// <param name="array">The .NET buffer.</param>
        /// <returns>The WinRT buffer.</returns>
        public static IBuffer ToBuffer(this byte[] array)
        {
            Requires.NotNull(array, "array");

            return Platform.CryptographicBuffer.CreateFromByteArray(array);
        }
    }
}
