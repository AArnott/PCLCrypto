//-----------------------------------------------------------------------
// <copyright file="IRandomNumberGenerator.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Provides cryptographically strong random number generation.
    /// </summary>
    public interface IRandomNumberGenerator
    {
        /// <summary>
        /// Fills a buffer with random data.
        /// </summary>
        /// <param name="buffer">The buffer to fill.</param>
        void GetBytes(byte[] buffer);
    }
}
