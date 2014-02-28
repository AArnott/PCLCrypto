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
    using Validation;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// Exposes the WinRT implementation of <see cref="IRandomNumberGenerator"/>.
    /// </summary>
    internal class RandomNumberGenerator : IRandomNumberGenerator
    {
        /// <inheritdoc/>
        public void GetBytes(byte[] buffer)
        {
            Requires.NotNull(buffer, "buffer");

            var windowsBuffer = Platform.CryptographicBuffer.GenerateRandom((uint)buffer.Length);
            Array.Copy(windowsBuffer.ToArray(), buffer, buffer.Length);
        }
    }
}
