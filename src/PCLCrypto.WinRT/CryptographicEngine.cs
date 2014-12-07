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
    using Windows.Storage.Streams;
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

            var keyClass = (CryptographicKey)key;
            if (keyClass.SymmetricAlgorithmProvider != null)
            {
                bool paddingInUse = keyClass.SymmetricAlgorithmProvider.Algorithm.GetPadding() != SymmetricAlgorithmPadding.None;
                Requires.Argument(paddingInUse || this.IsValidInputSize(keyClass, data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            }

            try
            {
                return Platform.Core.CryptographicEngine.Encrypt(
                    keyClass.Key,
                    data.ToBuffer(),
                    iv.ToBuffer()).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }

        /// <inheritdoc />
        public ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var ownKey = (CryptographicKey)key;
            return GetTransformForBlockMode(ownKey, iv, true);
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            if (keyClass.SymmetricAlgorithmProvider != null)
            {
                Requires.Argument(this.IsValidInputSize(keyClass, data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            }

            return Platform.Core.CryptographicEngine.Decrypt(
                keyClass.Key,
                data.ToBuffer(),
                iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        public ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var ownKey = (CryptographicKey)key;
            return GetTransformForBlockMode(ownKey, iv, false);
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
        /// Gets an <see cref="ICryptoTransform"/> instance to use for a given cryptographic key.
        /// </summary>
        /// <param name="key">The cryptographic key to use in the transform.</param>
        /// <param name="iv">The initialization vector to use, when applicable.</param>
        /// <param name="encrypting"><c>true</c> if encrypting; <c>false</c> if decrypting.</param>
        /// <returns>An instance of <see cref="ICryptoTransform"/>.</returns>
        private static ICryptoTransform GetTransformForBlockMode(CryptographicKey key, byte[] iv, bool encrypting)
        {
            Requires.NotNull(key, "key");

            var bufferOperation = encrypting
               ? new Func<byte[], byte[]>(input => Platform.Core.CryptographicEngine.Encrypt(key.Key, input.ToBuffer(), iv.ToBuffer()).ToArray())
               : new Func<byte[], byte[]>(input => Platform.Core.CryptographicEngine.Decrypt(key.Key, input.ToBuffer(), iv.ToBuffer()).ToArray());
            return new BufferingCryptoTransform(bufferOperation);
        }

        /// <summary>
        /// Checks whether the given length is a valid one for an input buffer to the symmetric algorithm.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="lengthInBytes">The length of the input buffer in bytes.</param>
        /// <returns>
        ///   <c>true</c> if the size is allowed; <c>false</c> otherwise.
        /// </returns>
        private bool IsValidInputSize(CryptographicKey key, int lengthInBytes)
        {
            Requires.NotNull(key, "key");
            return lengthInBytes > 0 && lengthInBytes % key.SymmetricAlgorithmProvider.BlockLength == 0;
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
