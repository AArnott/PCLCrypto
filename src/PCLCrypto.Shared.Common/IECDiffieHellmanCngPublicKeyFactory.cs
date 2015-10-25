// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// A factory for <see cref="IECDiffieHellmanPublicKey"/> instances.
    /// </summary>
    public interface IECDiffieHellmanCngPublicKeyFactory
    {
        /// <summary>
        /// Deserializes an <see cref="IECDiffieHellmanPublicKey"/> from a byte array.
        /// </summary>
        /// <param name="publicKey">A public key (presumably from the other party).</param>
        /// <returns>An instance of <see cref="IECDiffieHellmanPublicKey"/>.</returns>
        IECDiffieHellmanPublicKey FromByteArray(byte[] publicKey);
    }
}
