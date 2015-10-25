// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
        /// An empty byte array.
        /// </summary>
        private static readonly byte[] EmptyByteArray = new byte[0];

        /// <summary>
        /// An empty buffer.
        /// </summary>
        private static readonly IBuffer EmptyBuffer = new Windows.Storage.Streams.Buffer(0);

        /// <summary>
        /// Converts a WinRT buffer to a .NET buffer.
        /// </summary>
        /// <param name="buffer">The WinRT buffer.</param>
        /// <returns>The .NET buffer. Null if <paramref name="buffer"/> was null.</returns>
        public static byte[] ToArray(this IBuffer buffer)
        {
            if (buffer == null)
            {
                return null;
            }

            if (buffer.Length == 0)
            {
                return EmptyByteArray; // CopyToByteArray produces a null array in this case, so we fix it here.
            }

            byte[] result;
            Platform.CryptographicBuffer.CopyToByteArray(buffer, out result);
            return result;
        }

        /// <summary>
        /// Converts a .NET buffer to a WinRT buffer.
        /// </summary>
        /// <param name="array">The .NET buffer.</param>
        /// <returns>The WinRT buffer. Null if <paramref name="array"/> was null.</returns>
        public static IBuffer ToBuffer(this byte[] array)
        {
            if (array == null)
            {
                return null;
            }

            if (array.Length == 0)
            {
                return EmptyBuffer; // CreateFromByteArray returns null in this case, so we fix it here.
            }

            return Platform.CryptographicBuffer.CreateFromByteArray(array);
        }
    }
}
