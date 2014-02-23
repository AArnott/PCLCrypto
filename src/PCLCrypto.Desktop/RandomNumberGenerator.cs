//-----------------------------------------------------------------------
// <copyright file="RandomNumberGenerator.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// Exposes the .NET Framework implementation of <see cref="IRandomNumberGenerator"/>.
    /// </summary>
    internal class RandomNumberGenerator : IRandomNumberGenerator
    {
        /// <summary>
        /// The thread-safe source for random numbers.
        /// </summary>
        private static readonly RNGCryptoServiceProvider RandomSource = new RNGCryptoServiceProvider();

        /// <inheritdoc/>
        public void GetBytes(byte[] buffer)
        {
            Requires.NotNull(buffer, "buffer");

            RandomSource.GetBytes(buffer);
        }
    }
}
