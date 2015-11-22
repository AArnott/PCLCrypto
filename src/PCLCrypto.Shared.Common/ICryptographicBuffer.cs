// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Contains static methods that implement data management functionality common
    /// to cryptographic operations.
    /// </summary>
    public interface ICryptographicBuffer
    {
        /// <summary>
        /// Compares two byte[] objects.
        /// </summary>
        /// <param name="object1">First buffer to be used for comparison.</param>
        /// <param name="object2">Second buffer to be used for comparison.</param>
        /// <returns>
        /// True specifies that the buffers are equal. Two buffers are equal if each
        /// code point in one matches the corresponding code point in the other.
        /// </returns>
        bool Compare(byte[] object1, byte[] object2);

        /// <summary>
        /// Converts a buffer to an encoded string.
        /// </summary>
        /// <param name="encoding">Encoding format.</param>
        /// <param name="buffer">Data to be encoded.</param>
        /// <returns>
        /// A string that contains the encoded data.
        /// </returns>
        string ConvertBinaryToString(Encoding encoding, byte[] buffer);

        /// <summary>
        /// Converts a string to an encoded buffer.
        /// </summary>
        /// <param name="value">String to be encoded.</param>
        /// <param name="encoding">Encoding format.</param>
        /// <returns>
        /// Encoded buffer.
        /// </returns>
        byte[] ConvertStringToBinary(string value, Encoding encoding);

        /// <summary>
        /// Copies a buffer to an array of bytes.
        /// </summary>
        /// <param name="buffer">Input buffer.</param>
        /// <param name="value">An array of bytes that contains the values copied from the input buffer.
        /// You must declare the array before calling this method and pass it by using
        /// the ref keyword.</param>
        void CopyToByteArray(byte[] buffer, out byte[] value);

        /// <summary>
        /// Creates a buffer from an input byte array.
        /// </summary>
        /// <param name="value">An array of bytes used to create the buffer.</param>
        /// <returns>
        /// Output buffer.
        /// </returns>
        byte[] CreateFromByteArray(byte[] value);

        /// <summary>
        /// Decodes a string that has been base64 encoded.
        /// </summary>
        /// <param name="value">Base64 encoded input string.</param>
        /// <returns>
        /// Output buffer that contains the decoded string.
        /// </returns>
        byte[] DecodeFromBase64String(string value);

        /// <summary>
        /// Decodes a string that has been hexadecimal encoded.
        /// </summary>
        /// <param name="value">Encoded input string.</param>
        /// <returns>
        /// Output buffer that contains the decoded string.
        /// </returns>
        byte[] DecodeFromHexString(string value);

        /// <summary>
        /// Encodes a buffer to a base64 string.
        /// </summary>
        /// <param name="buffer">Input buffer.</param>
        /// <returns>
        /// Base64-encoded output string.
        /// </returns>
        string EncodeToBase64String(byte[] buffer);

        /// <summary>
        /// Encodes a buffer to a hexadecimal string.
        /// </summary>
        /// <param name="buffer">Input buffer.</param>
        /// <returns>
        /// Hexadecimal encoded output string.
        /// </returns>
        string EncodeToHexString(byte[] buffer);

        /// <summary>
        /// Creates a buffer that contains random data.
        /// </summary>
        /// <param name="length">Length, in bytes, of the buffer to create.</param>
        /// <returns>
        /// Output buffer that contains the random data.
        /// </returns>
        byte[] GenerateRandom(int length);

        /// <summary>
        /// Creates a random number.
        /// </summary>
        /// <returns>
        /// Integer that contains the random data.
        /// </returns>
        uint GenerateRandomNumber();
    }
}
