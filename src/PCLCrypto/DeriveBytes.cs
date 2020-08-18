// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft;

#pragma warning disable CA5379 // Do Not Use Weak Key Derivation Function Algorithm

    /// <summary>
    /// Exposes the .NET Framework implementation of <see cref="IDeriveBytes"/>.
    /// </summary>
    internal class DeriveBytes : IDeriveBytes
    {
        /// <inheritdoc/>
        public byte[] GetBytes(string keyMaterial, byte[] salt, int iterations, int countBytes, HashAlgorithmName hashAlgorithm)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, nameof(salt));
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

#if NETSTANDARD2_0
            if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                using var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations);
                return keyStrengthening.GetBytes(countBytes);
            }

            throw new NotImplementedByReferenceAssemblyException();
#else
            using var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations, hashAlgorithm);
            return keyStrengthening.GetBytes(countBytes);
#endif
        }

        /// <inheritdoc/>
        public byte[] GetBytes(byte[] keyMaterial, byte[] salt, int iterations, int countBytes, HashAlgorithmName hashAlgorithm)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, nameof(salt));
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

#if NETSTANDARD2_0
            if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                using var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations);
                return keyStrengthening.GetBytes(countBytes);
            }

            throw new NotImplementedByReferenceAssemblyException();
#else
            using var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations, hashAlgorithm);
            return keyStrengthening.GetBytes(countBytes);
#endif
        }
    }
}
