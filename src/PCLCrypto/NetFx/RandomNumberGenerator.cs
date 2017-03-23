// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
    internal class RandomNumberGenerator : System.Security.Cryptography.RandomNumberGenerator, IRandomNumberGenerator
    {
        /// <summary>
        /// The thread-safe source for random numbers.
        /// </summary>
#if SILVERLIGHT
        private static readonly RNGCryptoServiceProvider RandomSource = new RNGCryptoServiceProvider();
#else
        private static readonly System.Security.Cryptography.RandomNumberGenerator RandomSource = RandomNumberGenerator.Create();
#endif

        /// <inheritdoc/>
        public override void GetBytes(byte[] buffer)
        {
            RandomSource.GetBytes(buffer);
        }

#if !WINDOWS_PHONE && !SILVERLIGHT && !NETCOREAPP1_0
        /// <inheritdoc/>
        public override void GetNonZeroBytes(byte[] data)
        {
            RandomSource.GetNonZeroBytes(data);
        }
#endif
    }
}
