// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
        /// Gets the allowed key sizes.
        /// </summary>
        IReadOnlyList<KeySizes> LegalKeySizes { get; }

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
        /// <param name="blobType">Type of the blob.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo);

        /// <summary>
        /// Creates a cryptographic key based on the specified key material.
        /// </summary>
        /// <param name="keyBlob">The blob to deserialize.</param>
        /// <param name="blobType">Type of the blob.</param>
        /// <returns>The cryptographic key.</returns>
        ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
    }
}
