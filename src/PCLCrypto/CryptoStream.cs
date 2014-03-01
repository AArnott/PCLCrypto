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
        /// The input buffer.
        /// </summary>
        private readonly byte[] inputBuffer;

        /// <summary>
        /// The output buffer.
        /// </summary>
        private readonly byte[] outputBuffer;

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
            this.transform.TransformFinalBlock(new byte[0], 0, 0);
            this.HasFlushedFinalBlock = true;
        }

        #region Stream methods

        /// <inheritdoc />
        public override void Flush()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
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
            throw new NotImplementedException();
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
