//-----------------------------------------------------------------------
// <copyright file="CryptoStream.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// Defines a stream that links data streams to cryptographic transformations.
    /// </summary>
    public class CryptoStream : Stream
    {
        /// <summary>
        /// The stream that is read from or written to with each I/O operation.
        /// </summary>
        private readonly Stream chainedStream;

        /// <summary>
        /// The crypto transform to use for each block.
        /// </summary>
        private readonly ICryptoTransform transform;

        /// <summary>
        /// The read/write mode of this stream.
        /// </summary>
        private readonly CryptoStreamMode mode;

        /// <summary>
        /// Data that has not yet been transformed.
        /// </summary>
        private readonly byte[] inputBuffer;

        /// <summary>
        /// Data that has been transformed but not flushed.
        /// </summary>
        private byte[] outputBuffer;

        /// <summary>
        /// The number of valid bytes in <see cref="inputBuffer"/>.
        /// </summary>
        private int inputBufferSize;

        /// <summary>
        /// The number of valid bytes in <see cref="outputBuffer"/>.
        /// </summary>
        private int outputBufferSize;

        /// <summary>
        /// The index of the first valid byte in <see cref="outputBuffer"/>.
        /// This advances when Read is called with a smaller buffer than we have bytes available.
        /// </summary>
        private int outputBufferIndex;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptoStream"/> class.
        /// </summary>
        /// <param name="stream">The stream to write to or read from.</param>
        /// <param name="transform">The cryptographic operation to use for transforming data.</param>
        /// <param name="mode">The mode of operation.</param>
        public CryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
        {
            Requires.NotNull(stream, "stream");
            Requires.NotNull(transform, "transform");

            if (mode == CryptoStreamMode.Read)
            {
                Requires.Argument(stream.CanRead, "stream", "Stream is not readable.");
            }
            else if (mode == CryptoStreamMode.Write)
            {
                Requires.Argument(stream.CanWrite, "stream", "Stream is not writeable.");
            }
            else
            {
                Requires.That(false, "mode", "Unsupported mode.");
            }

            this.chainedStream = stream;
            this.transform = transform;
            this.mode = mode;
            this.inputBuffer = new byte[transform.InputBlockSize];
            this.outputBuffer = new byte[transform.OutputBlockSize];
        }

        /// <summary>
        /// Gets a value indicating whether the final buffer block has been written to the underlying stream. 
        /// </summary>
        public bool HasFlushedFinalBlock { get; private set; }

        #region Stream Properties

        /// <inheritdoc />
        public override bool CanRead
        {
            get { return this.mode == CryptoStreamMode.Read; }
        }

        /// <inheritdoc />
        public override bool CanSeek
        {
            get { return false; }
        }

        /// <inheritdoc />
        public override bool CanWrite
        {
            get { return this.mode == CryptoStreamMode.Write; }
        }

        /// <inheritdoc />
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        /// <inheritdoc />
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        #endregion

        /// <summary>
        /// Updates the underlying data source or repository with the current state of the buffer, then clears the buffer.
        /// </summary>
        /// <remarks>
        /// Calling the Close method will call FlushFinalBlock. If you do not call Close, call FlushFinalBlock to complete flushing the buffer. Call FlushFinalBlock only when all stream activity is complete.
        /// </remarks>
        public void FlushFinalBlock()
        {
            byte[] final = this.transform.TransformFinalBlock(this.inputBuffer, 0, this.inputBufferSize);
            this.chainedStream.Write(final, 0, final.Length);
            this.HasFlushedFinalBlock = true;

            // Propagate to the inner stream, as appropriate.
            var inner = this.chainedStream as CryptoStream;
            if (inner != null)
            {
                if (!inner.HasFlushedFinalBlock)
                {
                    inner.FlushFinalBlock();
                }
            }
            else
            {
                this.chainedStream.Flush();
            }

            // Clear buffers since they may contain security sensitive data.
            Array.Clear(this.inputBuffer, 0, this.inputBuffer.Length);
            Array.Clear(this.outputBuffer, 0, this.outputBuffer.Length);
        }

        #region Stream methods

        /// <inheritdoc />
        public override void Flush()
        {
            // Don't do anything here.
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            Requires.NotNull(buffer, "buffer");
            Requires.Range(offset >= 0, "offset");
            Requires.Range(count >= 0, "count");
            if (!this.CanRead)
            {
                throw new NotSupportedException();
            }

            int bytesCopied = 0;
            while (count > 0 && (!this.HasFlushedFinalBlock || this.outputBufferSize > 0))
            {
                if (this.outputBufferSize > 0)
                {
                    int bytesToCopy = Math.Min(count, this.outputBufferSize);
                    Array.Copy(this.outputBuffer, this.outputBufferIndex, buffer, offset, bytesToCopy);
                    count -= bytesToCopy;
                    offset += bytesToCopy;
                    bytesCopied += bytesToCopy;
                    this.outputBufferSize -= bytesToCopy;
                    this.outputBufferIndex = this.outputBufferSize == 0
                        ? 0
                        : this.outputBufferIndex + bytesToCopy;
                    continue;
                }

                // Only prepare to execute a transform if we have an empty output buffer.
                if (this.outputBufferSize == 0 && !this.HasFlushedFinalBlock)
                {
                    // Try to fill our input buffer.
                    int requestedBytes = this.inputBuffer.Length - this.inputBufferSize;
                    if (requestedBytes > 0)
                    {
                        int bytesRead = this.chainedStream.Read(this.inputBuffer, this.inputBufferSize, requestedBytes);
                        if (bytesRead == 0)
                        {
                            // When an attempt to read a stream results in zero bytes read,
                            // it means we've reached the end of the stream.
                            // Run the final transform and use its output as our final
                            // output buffer.
                            Array.Clear(this.outputBuffer, 0, this.outputBuffer.Length);
                            this.outputBuffer = this.transform.TransformFinalBlock(this.inputBuffer, 0, this.inputBufferSize);
                            this.inputBufferSize = 0;
                            this.HasFlushedFinalBlock = true;
                            this.outputBufferSize = this.outputBuffer.Length;
                            Assumes.True(this.outputBufferIndex == 0);
                            continue;
                        }

                        this.inputBufferSize += bytesRead;
                    }

                    // If we filled the input buffer, execute the transform.
                    if (this.inputBufferSize == this.inputBuffer.Length)
                    {
                        this.outputBufferSize = this.transform.TransformBlock(this.inputBuffer, 0, this.inputBuffer.Length, this.outputBuffer, 0);
                        this.inputBufferSize = 0;
                    }
                }
            }

            return bytesCopied;
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            Requires.NotNull(buffer, "buffer");
            Requires.Range(offset >= 0, "offset");
            Requires.Range(count >= 0, "count");
            if (!this.CanWrite)
            {
                throw new NotSupportedException();
            }

            while (count > 0)
            {
                if (this.inputBufferSize == 0 && this.transform.CanTransformMultipleBlocks)
                {
                    int multiple = count / this.inputBuffer.Length;
                    if (multiple > 1)
                    {
                        byte[] tempOutputBuffer = new byte[this.transform.OutputBlockSize * multiple];
                        int inputBytesToTransform = multiple * this.transform.InputBlockSize;
                        int transformedBytes = this.transform.TransformBlock(buffer, offset, inputBytesToTransform, tempOutputBuffer, 0);
                        count -= inputBytesToTransform;
                        offset += inputBytesToTransform;
                        this.chainedStream.Write(tempOutputBuffer, 0, transformedBytes);
                        Array.Clear(tempOutputBuffer, 0, tempOutputBuffer.Length);
                    }
                }

                int copiedBytes = Math.Min(count, this.inputBuffer.Length - this.inputBufferSize);
                Array.Copy(buffer, offset, this.inputBuffer, this.inputBufferSize, copiedBytes);
                count -= copiedBytes;
                offset += copiedBytes;
                this.inputBufferSize += copiedBytes;
                if (this.inputBufferSize == this.inputBuffer.Length)
                {
                    int transformedBytes = this.transform.TransformBlock(this.inputBuffer, 0, this.inputBuffer.Length, this.outputBuffer, 0);
                    this.inputBufferSize = 0;
                    this.chainedStream.Write(this.outputBuffer, 0, transformedBytes);
                }
            }
        }

        #endregion

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (!this.HasFlushedFinalBlock)
                    {
                        this.FlushFinalBlock();
                    }

                    this.chainedStream.Dispose();

                    // Clear all buffers since they could contain security data.
                    Array.Clear(this.inputBuffer, 0, this.inputBuffer.Length);
                    Array.Clear(this.outputBuffer, 0, this.outputBuffer.Length);
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
    }
}
