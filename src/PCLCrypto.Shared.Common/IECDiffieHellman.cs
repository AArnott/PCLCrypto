//-----------------------------------------------------------------------
// <copyright file="IECDiffieHellman.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
