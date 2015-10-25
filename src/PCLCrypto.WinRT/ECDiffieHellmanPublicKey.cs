// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using Validation;
    using static PInvoke.BCrypt;

    internal class ECDiffieHellmanPublicKey : IECDiffieHellmanPublicKey
    {
        private readonly SafeKeyHandle keyHandle;

        internal ECDiffieHellmanPublicKey(SafeKeyHandle keyHandle)
        {
            Requires.NotNull(keyHandle, nameof(keyHandle));

            this.keyHandle = keyHandle;
        }

        internal SafeKeyHandle Key => this.keyHandle;

        public byte[] ToByteArray()
        {
            return BCryptExportKey(this.keyHandle, null, AsymmetricKeyBlobTypes.EccPublic);
        }
    }
}
