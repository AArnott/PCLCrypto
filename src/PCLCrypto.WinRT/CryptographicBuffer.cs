//-----------------------------------------------------------------------
// <copyright file="CryptographicBuffer.cs" company="Andrew Arnott">
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
    using Platform = Windows.Security.Cryptography.CryptographicBuffer;

    /// <summary>
    /// The WinRT implementation of the <see cref="ICryptographicBuffer"/> interface.
    /// </summary>
    internal class CryptographicBuffer : ICryptographicBuffer
    {
        /// <summary>
        /// An empty byte array.
        /// </summary>
        private static readonly byte[] EmptyBuffer = new byte[0];

        /// <inheritdoc/>
        public bool Compare(byte[] object1, byte[] object2)
        {
            Requires.NotNull(object1, "object1");
            Requires.NotNull(object2, "object2");

            return Platform.Compare(object1.ToBuffer(), object2.ToBuffer());
        }

        /// <inheritdoc/>
        public string ConvertBinaryToString(Encoding encoding, byte[] buffer)
        {
            Requires.NotNull(encoding, "encoding");
            Requires.NotNull(buffer, "buffer");

            return encoding.GetString(buffer, 0, buffer.Length);
        }

        /// <inheritdoc/>
        public byte[] ConvertStringToBinary(string value, Encoding encoding)
        {
            Requires.NotNull(value, "value");
            Requires.NotNull(encoding, "encoding");

            return encoding.GetBytes(value);
        }

        /// <inheritdoc/>
        public void CopyToByteArray(byte[] buffer, out byte[] value)
        {
            Requires.NotNull(buffer, "buffer");

            value = new byte[buffer.Length];
            Array.Copy(buffer, value, buffer.Length);
        }

        /// <inheritdoc/>
        public byte[] CreateFromByteArray(byte[] value)
        {
            Requires.NotNull(value, "value");

            var result = new byte[value.Length];
            Array.Copy(value, result, value.Length);
            return result;
        }

        /// <inheritdoc/>
        public byte[] DecodeFromBase64String(string value)
        {
            return Convert.FromBase64String(value);
        }

        /// <inheritdoc/>
        public byte[] DecodeFromHexString(string value)
        {
            Requires.NotNull(value, "value");

            if (value.Length == 0)
            {
                return EmptyBuffer;
            }

            try
            {
                return Platform.DecodeFromHexString(value).ToArray();
            }
            catch (Exception ex)
            {
                throw new ArgumentException(ex.Message, nameof(value), ex);
            }
        }

        /// <inheritdoc/>
        public string EncodeToBase64String(byte[] buffer)
        {
            Requires.NotNull(buffer, "buffer");

            return Convert.ToBase64String(buffer);
        }

        /// <inheritdoc/>
        public string EncodeToHexString(byte[] buffer)
        {
            Requires.NotNull(buffer, "buffer");

            return Platform.EncodeToHexString(buffer.ToBuffer());
        }

        /// <inheritdoc/>
        public byte[] GenerateRandom(uint length)
        {
            return Platform.GenerateRandom(length).ToArray();
        }

        /// <inheritdoc/>
        public uint GenerateRandomNumber()
        {
            return Platform.GenerateRandomNumber();
        }
    }
}
