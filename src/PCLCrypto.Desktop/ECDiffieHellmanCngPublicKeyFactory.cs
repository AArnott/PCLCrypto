//-----------------------------------------------------------------------
// <copyright file="ECDiffieHellmanCngPublicKeyFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
