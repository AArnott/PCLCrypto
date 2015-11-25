// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    /// <summary>
    /// A crypto transform that can do no work incrementally, but does it all at the end.
    /// </summary>
    /// <remarks>
    /// Sadly, this is necessary because WinRT offers no incremental encryption/decryption
    /// APIs.
    /// </remarks>
    internal class BufferingCryptoTransform : ICryptoTransform
    {
        /// <summary>
        /// The buffering stream.
        /// </summary>
        private readonly MemoryStream bufferingStream = new MemoryStream();

        /// <summary>
        /// The transform to run when all bytes are collected.
        /// </summary>
        private readonly Func<byte[], byte[]> transform;

        /// <summary>
        /// Initializes a new instance of the <see cref="BufferingCryptoTransform"/> class.
        /// </summary>
        /// <param name="transform">The transform to run when all bytes are collected.</param>
        internal BufferingCryptoTransform(Func<byte[], byte[]> transform)
        {
            Requires.NotNull(transform, "transform");
            this.transform = transform;
        }

        /// <inheritdoc />
        public bool CanReuseTransform
        {
            get { return false; }
        }

        /// <inheritdoc />
        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <inheritdoc />
        public int InputBlockSize
        {
            get { return 1; }
        }

        /// <inheritdoc />
        public int OutputBlockSize
        {
            get { return 1; }
        }

        /// <inheritdoc />
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
            return 0;
        }

        /// <inheritdoc />
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
            return this.transform(this.bufferingStream.ToArray());
        }

        /// <inheritdoc />
        public void Dispose()
        {
            this.bufferingStream.Dispose();
        }
    }
}
