//-----------------------------------------------------------------------
// <copyright file="CryptographicEngine.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
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
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return Platform.Core.CryptographicEngine.Encrypt(
                ((CryptographicKey)key).Key,
                data.ToBuffer(),
                iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            return new BufferingCryptoTransform(
                data => this.Encrypt(key, data, iv));
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return Platform.Core.CryptographicEngine.Decrypt(
                ((CryptographicKey)key).Key,
                data.ToBuffer(),
                iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            return new BufferingCryptoTransform(
                data => this.Decrypt(key, data, iv));
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
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
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

            return Platform.Core.CryptographicEngine.VerifySignature(
                ExtractPlatformKey(key),
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        public bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            var keyClass = (CryptographicKey)key;
            return Platform.Core.CryptographicEngine.VerifySignatureWithHashInput(
                keyClass.Key,
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize)
        {
            var platformKey = ((CryptographicKey)key).Key;
            var platformParameters = ((KeyDerivationParameters)parameters).Parameters;
            return Platform.Core.CryptographicEngine.DeriveKeyMaterial(platformKey, platformParameters, (uint)desiredKeySize).ToArray();
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
