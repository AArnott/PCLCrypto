//-----------------------------------------------------------------------
// <copyright file="WinRTCryptographicHash.cs" company="Andrew Arnott">
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
    /// The WinRT implementation of the <see cref="CryptographicHash"/> interface.
    /// </summary>
    internal class WinRTCryptographicHash : CryptographicHash
    {
        /// <summary>
        /// The platform-specific hash object.
        /// </summary>
        private readonly Platform.Core.CryptographicHash platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="WinRTCryptographicHash"/> class.
        /// </summary>
        /// <param name="platformHash">The platform hash.</param>
        internal WinRTCryptographicHash(Platform.Core.CryptographicHash platformHash)
        {
            Requires.NotNull(platformHash, "platformHash");
            this.platform = platformHash;
        }

        /// <inheritdoc />
        public override void Append(byte[] data)
        {
            this.platform.Append(data.ToBuffer());
        }

        /// <inheritdoc />
        public override byte[] GetValueAndReset()
        {
            return this.platform.GetValueAndReset().ToArray();
        }
    }
}
