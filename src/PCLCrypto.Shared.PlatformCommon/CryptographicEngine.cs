// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicEngine"/>.
    /// </summary>
    internal class CryptographicEngine : ICryptographicEngine
    {
        /// <inheritdoc />
        public byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Encrypt(data, iv);
        }

        /// <inheritdoc />
        public ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateEncryptor(iv);
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Decrypt(data, iv);
        }

        /// <inheritdoc />
        public ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateDecryptor(iv);
        }

        /// <inheritdoc />
        public byte[] Sign(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).Sign(data);
        }

        /// <inheritdoc />
        public byte[] SignHashedData(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).SignHash(data);
        }

        /// <inheritdoc />
        public bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            return ((CryptographicKey)key).VerifySignature(data, signature);
        }

        /// <inheritdoc />
        public bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "paramName");

            return ((CryptographicKey)key).VerifyHash(data, signature);
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize)
        {
            return ((CryptographicKey)key).DeriveKeyMaterial(parameters, desiredKeySize);
        }
    }
}
