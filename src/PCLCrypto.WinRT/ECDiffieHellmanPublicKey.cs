// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Linq;
    using Validation;
    using static PInvoke.BCrypt;

    /// <summary>
    /// A WinRT implementation of the <see cref="IECDiffieHellmanPublicKey"/> interface.
    /// </summary>
    internal class ECDiffieHellmanPublicKey : IECDiffieHellmanPublicKey
    {
        private readonly SafeKeyHandle keyHandle;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDiffieHellmanPublicKey"/> class.
        /// </summary>
        /// <param name="keyHandle">The underlying platform public key.</param>
        internal ECDiffieHellmanPublicKey(SafeKeyHandle keyHandle)
        {
            Requires.NotNull(keyHandle, nameof(keyHandle));

            this.keyHandle = keyHandle;
        }

        /// <summary>
        /// Gets the platform-defined public key.
        /// </summary>
        internal SafeKeyHandle Key => this.keyHandle;

        /// <inheritdoc />
        public byte[] ToByteArray()
        {
            return BCryptExportKey(this.keyHandle, null, AsymmetricKeyBlobTypes.EccPublic).ToArray();
        }
    }
}
