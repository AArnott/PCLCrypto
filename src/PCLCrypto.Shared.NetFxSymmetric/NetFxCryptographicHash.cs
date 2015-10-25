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
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="CryptographicHash"/> interface.
    /// </summary>
    internal class NetFxCryptographicHash : CryptographicHash
    {
        /// <summary>
        /// A zero-length byte array.
        /// </summary>
        private static readonly byte[] EmptyBlock = new byte[0];

        /// <summary>
        /// A value indicating whether <see cref="TransformFinalBlock"/> has been called.
        /// </summary>
        private bool transformedFinalBlock;

        /// <summary>
        /// Initializes a new instance of the <see cref="NetFxCryptographicHash"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal NetFxCryptographicHash(Platform.HashAlgorithm algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");

            this.Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the platform-specific hash algorithm.
        /// </summary>
        protected Platform.HashAlgorithm Algorithm { get; private set; }

        /// <inheritdoc />
        protected override bool CanReuseTransform
        {
            get { return this.Algorithm.CanReuseTransform; }
        }

        /// <inheritdoc />
        protected override bool CanTransformMultipleBlocks
        {
            get { return this.Algorithm.CanTransformMultipleBlocks; }
        }

        /// <inheritdoc />
        protected override int InputBlockSize
        {
            get { return this.Algorithm.InputBlockSize; }
        }

        /// <inheritdoc />
        protected override int OutputBlockSize
        {
            get { return this.Algorithm.OutputBlockSize; }
        }

        /// <inheritdoc />
        public override void Append(byte[] data)
        {
            Requires.NotNull(data, "data");
            this.TransformBlock(data, 0, data.Length, null, 0);
        }

        /// <inheritdoc />
        public override byte[] GetValueAndReset()
        {
            if (!this.transformedFinalBlock)
            {
                this.TransformFinalBlock(EmptyBlock, 0, 0);
            }

            byte[] hash = this.Algorithm.Hash;
            this.Algorithm.Initialize();
            this.transformedFinalBlock = false;
            return hash;
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            var disposable = this.Algorithm as IDisposable;
            if (disposable != null)
            {
                disposable.Dispose();
            }
        }

        /// <inheritdoc />
        protected override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return this.Algorithm.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        /// <inheritdoc />
        protected override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            Verify.Operation(!this.transformedFinalBlock, "Already transformed the final block.");
            this.transformedFinalBlock = true;
            return this.Algorithm.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }
    }
}
