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
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public byte[] ConvertStringToBinary(string value, Encoding encoding)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public void CopyToByteArray(byte[] buffer, out byte[] value)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public byte[] CreateFromByteArray(byte[] value)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public byte[] DecodeFromBase64String(string value)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public byte[] DecodeFromHexString(string value)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public string EncodeToBase64String(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public string EncodeToHexString(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public byte[] GenerateRandom(uint length)
        {
            var buffer = new byte[length];
            Crypto.RandomNumberGenerator.GetBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public uint GenerateRandomNumber()
        {
            byte[] buffer = new byte[sizeof(uint)];
            Crypto.RandomNumberGenerator.GetBytes(buffer);
            return BitConverter.ToUInt32(buffer, 0);
        }
    }
}
