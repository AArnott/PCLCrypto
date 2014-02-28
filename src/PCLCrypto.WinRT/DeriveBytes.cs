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
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Core;
    using Windows.Storage.Streams;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// Exposes the WinRT implementation of <see cref="IDeriveBytes"/>.
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

            IBuffer keyMaterialBuffer = Platform.CryptographicBuffer.ConvertStringToBinary(keyMaterial, BinaryStringEncoding.Utf8);
            return this.GetBytes(keyMaterialBuffer, salt.ToBuffer(), iterations, countBytes).ToArray();
        }

        /// <inheritdoc/>
        public byte[] GetBytes(byte[] keyMaterial, byte[] salt, int iterations, int countBytes)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, "salt");
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

            return this.GetBytes(keyMaterial.ToBuffer(), salt.ToBuffer(), iterations, countBytes).ToArray();
        }

        /// <summary>
        /// Derives a cryptographically strong key from the specified bytes.
        /// </summary>
        /// <param name="keyMaterial">The user-supplied password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The rounds of computation to use in deriving a stronger key. The larger this is, the longer attacks will take.</param>
        /// <param name="countBytes">The desired key size in bytes.</param>
        /// <returns>The generated key.</returns>
        public IBuffer GetBytes(IBuffer keyMaterial, IBuffer salt, int iterations, int countBytes)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");
            Requires.NotNull(salt, "salt");
            Requires.Range(iterations > 0, "iterations");
            Requires.Range(countBytes > 0, "countBytes");

            var keyDerivationProvider =
                Platform.Core.KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            var pbkdf2Parms =
                Platform.Core.KeyDerivationParameters.BuildForPbkdf2(salt, (uint)iterations);

            // create a key based on original key and derivation parameters
            var keyOriginal = keyDerivationProvider.CreateKey(keyMaterial);
            IBuffer result = Platform.Core.CryptographicEngine.DeriveKeyMaterial(keyOriginal, pbkdf2Parms, (uint)countBytes);
            return result;
        }
    }
}
