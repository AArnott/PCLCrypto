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
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// The WinRT implementation of the <see cref="CryptographicHash"/> interface.
    /// </summary>
    internal class WinRTCryptographicHash : CryptographicHash
    {
        /// <summary>
        /// The platform-specific hash object.
        /// </summary>
        private readonly Platform.Core.CryptographicHash platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="WinRTCryptographicHash"/> class.
        /// </summary>
        /// <param name="platformHash">The platform hash.</param>
        internal WinRTCryptographicHash(Platform.Core.CryptographicHash platformHash)
        {
            Requires.NotNull(platformHash, "platformHash");
            this.platform = platformHash;
        }

        /// <inheritdoc />
        protected override bool CanReuseTransform
        {
            get { return true; }
        }

        /// <inheritdoc />
        public override void Append(byte[] data)
        {
            this.platform.Append(data.ToBuffer());
        }

        /// <inheritdoc />
        public override byte[] GetValueAndReset()
        {
            return this.platform.GetValueAndReset().ToArray();
        }

        #region ICryptoTransform methods

        /// <inheritdoc />
        protected override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            byte[] buffer;
            if (inputCount < inputBuffer.Length)
            {
                buffer = new byte[inputCount];
                Array.Copy(inputBuffer, inputOffset, buffer, 0, inputCount);
            }
            else
            {
                buffer = inputBuffer;
            }

            this.Append(buffer);
            if (outputBuffer != null)
            {
                Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
            }

            return inputCount;
        }

        /// <inheritdoc />
        protected override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            this.TransformBlock(inputBuffer, inputOffset, inputCount, null, 0);
            if (inputCount == inputBuffer.Length)
            {
                return inputBuffer;
            }
            else
            {
                var buffer = new byte[inputCount];
                Array.Copy(inputBuffer, inputOffset, buffer, 0, inputCount);
                return buffer;
            }
        }

        #endregion
    }
}
