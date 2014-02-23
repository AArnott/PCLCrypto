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
    using System.Text;
    using System.Threading.Tasks;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// Exposes the .NET Framework implementation of <see cref="IRandomNumberGenerator"/>.
    /// </summary>
    internal class RandomNumberGenerator : IRandomNumberGenerator
    {
        /// <inheritdoc/>
        public void GetBytes(byte[] buffer)
        {
            var random = Platform.RandomNumberGenerator.Create();
            random.GetBytes(buffer);
        }
    }
}
