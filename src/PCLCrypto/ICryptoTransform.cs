// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Defines the basic operations of cryptographic transformations.
    /// </summary>
    public interface ICryptoTransform : IDisposable
    {
        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        bool CanReuseTransform { get; }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        bool CanTransformMultipleBlocks { get; }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        int InputBlockSize { get; }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        int OutputBlockSize { get; }

        /// <summary>
        /// Transforms the specified region of the input byte array and copies the resulting transform to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data. </param>
        /// <param name="outputBuffer">The output to which to write the transform. </param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data. </param>
        /// <returns>The number of bytes written.</returns>
        int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        /// <summary>
        /// Transforms the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data. </param>
        /// <returns>The computed transform.</returns>
        /// <remarks>
        /// TransformFinalBlock is a special function for transforming the last block or a partial block in the stream. It returns a new array that contains the remaining transformed bytes. A new array is returned, because the amount of information returned at the end might be larger than a single block when padding is added.
        /// </remarks>
        byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
    }
}
