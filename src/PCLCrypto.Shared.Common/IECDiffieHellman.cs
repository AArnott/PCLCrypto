// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// Provides functionality for the ECDiffieHellman algorithm.
    /// </summary>
    public interface IECDiffieHellman : IDisposable
    {
        /// <summary>
        /// Gets or sets the size, in bits, of the key modulus used by the asymmetric algorithm.
        /// </summary>
        /// <value>The size, in bits, of the key modulus used by the asymmetric algorithm.</value>
        int KeySize { get; set; }

        /// <summary>
        /// Gets the public key to share with the other party in order to establish a shared secret.
        /// </summary>
        IECDiffieHellmanPublicKey PublicKey { get; }

        /// <summary>
        /// Derives bytes that can be used as a key, given another party's public key.
        /// </summary>
        /// <param name="otherParty">The other party's public key.</param>
        /// <returns>The key material from the key exchange with the other party’s public key.</returns>
        byte[] DeriveKeyMaterial(IECDiffieHellmanPublicKey otherParty);
    }
}
