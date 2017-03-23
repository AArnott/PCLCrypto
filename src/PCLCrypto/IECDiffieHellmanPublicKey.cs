// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Provides access to the public key used as part of an instance
    /// of <see cref="IECDiffieHellman"/>.
    /// </summary>
    public interface IECDiffieHellmanPublicKey
    {
        /// <summary>
        /// Serializes the ECDiffieHellmanPublicKey key BLOB to a byte array.
        /// </summary>
        /// <returns>A byte array.</returns>
        byte[] ToByteArray();
    }
}
