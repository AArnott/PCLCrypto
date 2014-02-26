//-----------------------------------------------------------------------
// <copyright file="CryptographicHash.cs" company="Andrew Arnott">
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
    /// The WinRT implementation of the <see cref="ICryptographicHash"/> interface.
    /// </summary>
    internal class CryptographicHash : ICryptographicHash
    {
        /// <summary>
        /// The platform-specific hash object.
        /// </summary>
        private readonly Platform.Core.CryptographicHash platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicHash"/> class.
        /// </summary>
        /// <param name="platformHash">The platform hash.</param>
        internal CryptographicHash(Platform.Core.CryptographicHash platformHash)
        {
            Requires.NotNull(platformHash, "platformHash");
            this.platform = platformHash;
        }

        /// <inheritdoc />
        public void Append(byte[] data)
        {
            this.platform.Append(data.ToBuffer());
        }

        /// <inheritdoc />
        public byte[] GetValueAndReset()
        {
            return this.platform.GetValueAndReset().ToArray();
        }
    }
}
