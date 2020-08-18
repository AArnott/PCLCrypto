// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System.Security.Cryptography;

    /// <summary>
    /// Provides fixed-length key derivation from passwords or byte buffers of arbitrary size.
    /// </summary>
    public interface IDeriveBytes
    {
        /// <summary>
        /// Derives a cryptographically strong key from the specified password.
        /// </summary>
        /// <param name="keyMaterial">The user-supplied password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The rounds of computation to use in deriving a stronger key. The larger this is, the longer attacks will take.</param>
        /// <param name="countBytes">The desired key size in bytes.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use.</param>
        /// <returns>The generated key.</returns>byte[] GetBytes(string keyMaterial, byte[] salt, int iterations, int countBytes);
        byte[] GetBytes(string keyMaterial, byte[] salt, int iterations, int countBytes, HashAlgorithmName hashAlgorithm);

        /// <inheritdoc cref="GetBytes(string, byte[], int, int, HashAlgorithmName)"/>
        byte[] GetBytes(byte[] keyMaterial, byte[] salt, int iterations, int countBytes, HashAlgorithmName hashAlgorithm);
    }
}
