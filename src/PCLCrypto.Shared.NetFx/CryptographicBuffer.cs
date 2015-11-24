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
    /// The .NET Framework implementation of the <see cref="ICryptographicBuffer"/> interface.
    /// </summary>
    internal class CryptographicBuffer : ICryptographicBuffer
    {
        /// <inheritdoc/>
        public bool Compare(byte[] object1, byte[] object2)
        {
            return CryptoUtilities.BufferEquals(object1, object2);
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
            Requires.Argument(value.Length % 2 == 0, "value", "Bad length.");

            var buffer = new byte[value.Length / 2];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
            }

            return buffer;
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

            var builder = new StringBuilder(buffer.Length * 2);
            for (int i = 0; i < buffer.Length; i++)
            {
                builder.AppendFormat("{0:x2}", buffer[i]);
            }

            return builder.ToString();
        }

        /// <inheritdoc/>
        public byte[] GenerateRandom(int length)
        {
            var buffer = new byte[length];
            NetFxCrypto.RandomNumberGenerator.GetBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public uint GenerateRandomNumber()
        {
            byte[] buffer = new byte[sizeof(uint)];
            NetFxCrypto.RandomNumberGenerator.GetBytes(buffer);
            return BitConverter.ToUInt32(buffer, 0);
        }
    }
}
