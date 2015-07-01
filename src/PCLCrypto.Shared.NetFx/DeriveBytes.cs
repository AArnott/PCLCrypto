//-----------------------------------------------------------------------
// <copyright file="DeriveBytes.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// Exposes the .NET Framework implementation of <see cref="IDeriveBytes"/>.
    /// </summary>
    internal class DeriveBytes : IDeriveBytes
    {
        /// <inheritdoc/>
        public byte[] GetBytes(string keyMaterial, byte[] salt, int iterations, int countBytes)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, "salt");
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

            using (var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations))
            {
                return keyStrengthening.GetBytes(countBytes);
            }
        }

        /// <inheritdoc/>
        public byte[] GetBytes(byte[] keyMaterial, byte[] salt, int iterations, int countBytes)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, "salt");
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

            using (var keyStrengthening = new Rfc2898DeriveBytes(keyMaterial, salt, iterations))
            {
                return keyStrengthening.GetBytes(countBytes);
            }
        }
    }
}
