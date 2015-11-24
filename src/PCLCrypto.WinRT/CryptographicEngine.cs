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

            return this.GetTransformForBlockMode(key, iv, true);
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

            return this.GetTransformForBlockMode(key, iv, false);
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

        /// <summary>
        /// Gets an <see cref="ICryptoTransform"/> instance to use for a given cryptographic key.
        /// </summary>
        /// <param name="key">The cryptographic key to use in the transform.</param>
        /// <param name="iv">The initialization vector to use, when applicable.</param>
        /// <param name="encrypting"><c>true</c> if encrypting; <c>false</c> if decrypting.</param>
        /// <returns>An instance of <see cref="ICryptoTransform"/>.</returns>
        private ICryptoTransform GetTransformForBlockMode(ICryptographicKey key, byte[] iv, bool encrypting)
        {
            Requires.NotNull(key, "key");

            var bufferOperation = encrypting
               ? new Func<byte[], byte[]>(input => this.Encrypt(key, input, iv))
               : new Func<byte[], byte[]>(input => this.Decrypt(key, input, iv));
            return new BufferingCryptoTransform(bufferOperation);
        }

        /// <summary>
        /// A crypto transform that can do no work incrementally, but does it all at the end.
        /// </summary>
        /// <remarks>
        /// Sadly, this is necessary because WinRT offers no incremental encryption/decryption
        /// APIs.
        /// </remarks>
        private class BufferingCryptoTransform : ICryptoTransform
        {
            /// <summary>
            /// The buffering stream.
            /// </summary>
            private readonly MemoryStream bufferingStream = new MemoryStream();

            /// <summary>
            /// The transform to run when all bytes are collected.
            /// </summary>
            private readonly Func<byte[], byte[]> transform;

            /// <summary>
            /// Initializes a new instance of the <see cref="BufferingCryptoTransform"/> class.
            /// </summary>
            /// <param name="transform">The transform to run when all bytes are collected.</param>
            internal BufferingCryptoTransform(Func<byte[], byte[]> transform)
            {
                Requires.NotNull(transform, "transform");
                this.transform = transform;
            }

            /// <inheritdoc />
            public bool CanReuseTransform
            {
                get { return false; }
            }

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks
            {
                get { return true; }
            }

            /// <inheritdoc />
            public int InputBlockSize
            {
                get { return 1; }
            }

            /// <inheritdoc />
            public int OutputBlockSize
            {
                get { return 1; }
            }

            /// <inheritdoc />
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
                return 0;
            }

            /// <inheritdoc />
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
                return this.transform(this.bufferingStream.ToArray());
            }

            /// <inheritdoc />
            public void Dispose()
            {
                this.bufferingStream.Dispose();
            }
        }
    }
}
