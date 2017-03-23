// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET implementation of <see cref="IECDiffieHellmanCngPublicKeyFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanCngPublicKeyFactory : IECDiffieHellmanCngPublicKeyFactory
    {
        /// <inheritdoc />
        public IECDiffieHellmanPublicKey FromByteArray(byte[] publicKey)
        {
            Requires.NotNull(publicKey, nameof(publicKey));

            return new ECDiffieHellmanPublicKey(
                Platform.ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, Platform.CngKeyBlobFormat.EccPublicBlob));
        }
    }
}
