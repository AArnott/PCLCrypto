// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET implementation of the <see cref="IECDiffieHellmanPublicKey"/> interface.
    /// </summary>
    internal class ECDiffieHellmanPublicKey : IECDiffieHellmanPublicKey
    {
        private readonly Platform.ECDiffieHellmanPublicKey publicKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDiffieHellmanPublicKey"/> class.
        /// </summary>
        /// <param name="publicKey">The underlying platform public key.</param>
        internal ECDiffieHellmanPublicKey(Platform.ECDiffieHellmanPublicKey publicKey)
        {
            Requires.NotNull(publicKey, nameof(publicKey));

            this.publicKey = publicKey;
        }

        /// <summary>
        /// Gets the platform-defined public key.
        /// </summary>
        internal Platform.ECDiffieHellmanPublicKey PlatformPublicKey => this.publicKey;

        /// <inheritdoc />
        public byte[] ToByteArray() => this.publicKey.ToByteArray();
    }
}
