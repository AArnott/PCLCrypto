// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents a reusable hashing object and contains the result of a hashing
    /// operation.
    /// </summary>
    public abstract class CryptographicHash : ICryptoTransform, IDisposable
    {
        #region ICryptoTransform Properties

        /// <inheritdoc />
        bool ICryptoTransform.CanReuseTransform
        {
            get { return this.CanReuseTransform; }
        }

        /// <inheritdoc />
        bool ICryptoTransform.CanTransformMultipleBlocks
        {
            get { return this.CanTransformMultipleBlocks; }
        }

        /// <inheritdoc />
        int ICryptoTransform.InputBlockSize
        {
            get { return this.InputBlockSize; }
        }

        /// <inheritdoc />
        int ICryptoTransform.OutputBlockSize
        {
            get { return this.OutputBlockSize; }
        }

        #endregion

        #region ICryptoTransform protected properties

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        protected virtual bool CanReuseTransform
        {
            get { return false; }
        }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        protected virtual bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        protected virtual int InputBlockSize
        {
            get { return 1; }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        protected virtual int OutputBlockSize
        {
            get { return 1; }
        }

        #endregion

        #region ICryptoTransform Methods

        /// <inheritdoc />
        int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return this.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        /// <inheritdoc />
        byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return this.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        #endregion

        /// <summary>
        /// Appends a binary encoded string to the data stored in the CryptographicHash
        /// object.
        /// </summary>
        /// <param name="data">Data to append.</param>
        public abstract void Append(byte[] data);

        /// <summary>
        /// Gets hashed data from the CryptographicHash object and resets the object.
        /// </summary>
        /// <returns>Hashed data.</returns>
        public abstract byte[] GetValueAndReset();

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
        }

        #region ICryptoTransform protected methods

        /// <summary>
        /// Transforms the specified region of the input byte array and copies the resulting transform to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write the transform.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>
        /// The number of bytes written.
        /// </returns>
        protected abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        /// <summary>
        /// Transforms the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <returns>
        /// The computed transform.
        /// </returns>
        /// <remarks>
        /// TransformFinalBlock is a special function for transforming the last block or a partial block in the stream. It returns a new array that contains the remaining transformed bytes. A new array is returned, because the amount of information returned at the end might be larger than a single block when padding is added.
        /// </remarks>
        protected abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);

        #endregion
    }
}
