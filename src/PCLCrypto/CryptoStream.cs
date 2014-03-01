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

    /// <summary>
    /// Defines a stream that links data streams to cryptographic transformations.
    /// </summary>
    public class CryptoStream : Stream
    {
        ////private readonly Stream chainedStream;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptoStream"/> class.
        /// </summary>
        /// <param name="stream">The stream to write to or read from.</param>
        /// <param name="transform">The cryptographic operation to use for transforming data.</param>
        /// <param name="mode">The mode of operation.</param>
        public CryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
        {
        }

        /// <summary>
        /// Gets a value indicating whether the final buffer block has been written to the underlying stream. 
        /// </summary>
        public bool HasFlushedFinalBlock { get; private set; }

        #region Stream Properties

        /// <inheritdoc />
        public override bool CanRead
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public override bool CanSeek
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public override bool CanWrite
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public override long Length
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }

            set
            {
                throw new NotImplementedException();
            }
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
    }
}
