//-----------------------------------------------------------------------
// <copyright file="JavaCryptographicHash.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Android.App;
    using Android.Content;
    using Android.OS;
    using Android.Runtime;
    using Android.Views;
    using Android.Widget;
    using Java.Security;
    using Validation;

    /// <summary>
    /// A Java MessageDigest implementation of the <see cref="CryptographicHash"/> interface.
    /// </summary>
    internal class JavaCryptographicHash : CryptographicHash
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JavaCryptographicHash"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal JavaCryptographicHash(MessageDigest algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");

            this.Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the platform-specific hash algorithm.
        /// </summary>
        protected MessageDigest Algorithm { get; private set; }

        /// <inheritdoc />
        public override void Append(byte[] data)
        {
            this.Algorithm.Update(data);
        }

        /// <inheritdoc />
        public override byte[] GetValueAndReset()
        {
            byte[] result = this.Algorithm.Digest();
            this.Algorithm.Reset();
            return result;
        }

        /// <inheritdoc />
        protected override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            this.Algorithm.Update(inputBuffer, inputOffset, inputCount);
            if (outputBuffer != null)
            {
                Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
            }

            return inputCount;
        }

        /// <inheritdoc />
        protected override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            this.Algorithm.Update(inputBuffer, inputOffset, inputCount);
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
    }
}