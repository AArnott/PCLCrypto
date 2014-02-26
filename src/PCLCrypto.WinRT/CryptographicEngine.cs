//-----------------------------------------------------------------------
// <copyright file="CryptographicEngine.cs" company="Andrew Arnott">
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
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// A WinRT implementation of <see cref="ICryptographicEngine"/>.
    /// </summary>
    internal class CryptographicEngine : ICryptographicEngine
    {
        /// <inheritdoc />
        public byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] Sign(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return Platform.Core.CryptographicEngine.Sign(
                ExtractPlatformKey(key),
                data.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public byte[] SignHashedData(ICryptographicKey key, byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            return Platform.Core.CryptographicEngine.VerifySignature(
                ExtractPlatformKey(key),
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        public bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Extracts the platform-specific key from the PCL version.
        /// </summary>
        /// <param name="key">The PCL key.</param>
        /// <returns>The platform-specific key.</returns>
        private static Platform.Core.CryptographicKey ExtractPlatformKey(ICryptographicKey key)
        {
            Requires.NotNull(key, "key");
            var platformKey = ((CryptographicKey)key).Key;
            return platformKey;
        }
    }
}
