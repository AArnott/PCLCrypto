// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using Windows.Storage.Streams;
    using static PInvoke.BCrypt;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// A WinRT implementation of <see cref="ICryptographicEngine"/>.
    /// </summary>
    internal class CryptographicEngine : ICryptographicEngine
    {
        /// <inheritdoc />
        public byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).Encrypt(data, iv);
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
            Requires.NotNull(key, nameof(key));
            Requires.NotNull(data, nameof(data));

            return ((CryptographicKey)key).Decrypt(data, iv);
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

            var keyClass = (WinRTCryptographicKey)key;
            return Platform.Core.CryptographicEngine.Sign(
                keyClass.Key,
                data.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public byte[] SignHashedData(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (WinRTCryptographicKey)key;
            return Platform.Core.CryptographicEngine.SignHashedData(
                keyClass.Key,
                data.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            var keyClass = (WinRTCryptographicKey)key;
            return Platform.Core.CryptographicEngine.VerifySignature(
                keyClass.Key,
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        public bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            var keyClass = (WinRTCryptographicKey)key;
            return Platform.Core.CryptographicEngine.VerifySignatureWithHashInput(
                keyClass.Key,
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize)
        {
            Requires.NotNull(key, nameof(key));

            var platformKey = ((WinRTCryptographicKey)key).Key;
            var platformParameters = ((KeyDerivationParameters)parameters).Parameters;
            return Platform.Core.CryptographicEngine.DeriveKeyMaterial(platformKey, platformParameters, (uint)desiredKeySize).ToArray();
        }
    }
}
