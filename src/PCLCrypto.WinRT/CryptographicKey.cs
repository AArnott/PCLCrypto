// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// A abstract base class for cryptographic operations implemented differently
    /// based on the type of key.
    /// </summary>
    internal abstract class CryptographicKey
    {
        /// <summary>
        /// Encrypts a buffer with the specified IV.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <returns>The ciphertext.</returns>
        internal abstract byte[] Encrypt(byte[] plaintext, byte[] iv);

        /// <summary>
        /// Decrypts a buffer with the specified IV.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <returns>The plaintext.</returns>
        internal abstract byte[] Decrypt(byte[] ciphertext, byte[] iv);
    }
}
