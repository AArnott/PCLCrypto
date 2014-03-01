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
    public abstract class CryptoStream : Stream
    {
        /// <summary>
        /// Gets a value indicating whether the final buffer block has been written to the underlying stream. 
        /// </summary>
        public abstract bool HasFlushedFinalBlock { get; }

        /// <summary>
        /// Updates the underlying data source or repository with the current state of the buffer, then clears the buffer.
        /// </summary>
        /// <remarks>
        /// Calling the Close method will call FlushFinalBlock. If you do not call Close, call FlushFinalBlock to complete flushing the buffer. Call FlushFinalBlock only when all stream activity is complete.
        /// </remarks>
        public abstract void FlushFinalBlock();
    }
}
