//-----------------------------------------------------------------------
// <copyright file="IAsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Provides access to asymmetric cryptographic algorithms of the platform.
    /// </summary>
    public interface IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Gets the asymmetric algorithm this provider manages keys for.
        /// </summary>
        AsymmetricAlgorithm Algorithm { get; }

        /// <summary>
        /// Creates a new cryptographic key.
        /// </summary>
        /// <param name="keySize">The size of the key (in bits).</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey CreateKeyPair(int keySize);

        /// <summary>
        /// Creates a cryptographic key based on the specified key material.
        /// </summary>
        /// <param name="keyBlob">The blob to deserialize.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportKeyPair(byte[] keyBlob);

        /// <summary>
        /// Creates a cryptographic key based on the specified key material.
        /// </summary>
        /// <param name="keyBlob">The blob to deserialize.</param>
        /// <param name="blobType">Type of the blob.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType);

        /// <summary>
        /// Creates a cryptographic key based on the specified key material.
        /// </summary>
        /// <param name="keyBlob">The blob to deserialize.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportPublicKey(byte[] keyBlob);

        /// <summary>
        /// Creates a cryptographic key based on the specified key material.
        /// </summary>
        /// <param name="keyBlob">The blob to deserialize.</param>
        /// <param name="blobType">Type of the blob.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType);
    }
}
