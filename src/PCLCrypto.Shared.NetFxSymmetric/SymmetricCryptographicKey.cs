// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicKey"/> for use with symmetric algorithms.
    /// </summary>
    internal class SymmetricCryptographicKey : CryptographicKey, ICryptographicKey, IDisposable
    {
        /// <summary>
        /// The platform's symmetric algorithm.
        /// </summary>
        private readonly Platform.SymmetricAlgorithm algorithm;

        /// <summary>
        /// The PCL algorithm enum.
        /// </summary>
        private readonly SymmetricAlgorithm pclAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryptographicKey"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm, initialized with the key.</param>
        /// <param name="pclAlgorithm">The PCL enum of the algorithm in use.</param>
        internal SymmetricCryptographicKey(Platform.SymmetricAlgorithm algorithm, SymmetricAlgorithm pclAlgorithm)
        {
            Requires.NotNull(algorithm, "algorithm");
            this.algorithm = algorithm;
            this.pclAlgorithm = pclAlgorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.algorithm.KeySize; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            var disposable = this.algorithm as IDisposable;
            if (disposable != null)
            {
                disposable.Dispose();
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            bool paddingInUse = this.pclAlgorithm.GetPadding() != SymmetricAlgorithmPadding.None;
            Requires.Argument(paddingInUse || this.IsValidInputSize(data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            Requires.Argument(iv == null || this.pclAlgorithm.UsesIV(), "iv", "IV supplied but does not apply to this cipher.");

            var encryptor = this.algorithm.CreateEncryptor(this.algorithm.Key, this.ThisOrDefaultIV(iv));
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            Requires.Argument(this.IsValidInputSize(data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            var decryptor = this.algorithm.CreateDecryptor(this.algorithm.Key, this.ThisOrDefaultIV(iv));
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            return new CryptoTransformAdaptor(
                this.algorithm.CreateEncryptor(this.algorithm.Key, this.ThisOrDefaultIV(iv)));
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            return new CryptoTransformAdaptor(
                this.algorithm.CreateDecryptor(this.algorithm.Key, this.ThisOrDefaultIV(iv)));
        }

        /// <summary>
        /// Creates a zero IV buffer.
        /// </summary>
        /// <param name="iv">The IV supplied by the caller.</param>
        /// <returns><paramref name="iv"/> if not null; otherwise a zero-filled buffer.</returns>
        private byte[] ThisOrDefaultIV(byte[] iv)
        {
            if (iv != null)
            {
                return iv;
            }
            else if (!this.pclAlgorithm.UsesIV())
            {
                // Don't create an IV when it doesn't apply.
                return null;
            }
            else
            {
                return new byte[this.algorithm.BlockSize / 8];
            }
        }

        /// <summary>
        /// Checks whether the given length is a valid one for an input buffer to the symmetric algorithm.
        /// </summary>
        /// <param name="lengthInBytes">The length of the input buffer in bytes.</param>
        /// <returns><c>true</c> if the size is allowed; <c>false</c> otherwise.</returns>
        private bool IsValidInputSize(int lengthInBytes)
        {
            return lengthInBytes > 0 && (lengthInBytes * 8) % this.algorithm.BlockSize == 0;
        }

        /// <summary>
        /// Adapts a platform ICryptoTransform to the PCL interface.
        /// </summary>
        private class CryptoTransformAdaptor : ICryptoTransform
        {
            /// <summary>
            /// The platform transform.
            /// </summary>
            private readonly Platform.ICryptoTransform transform;

            /// <summary>
            /// Initializes a new instance of the <see cref="CryptoTransformAdaptor"/> class.
            /// </summary>
            /// <param name="transform">The transform.</param>
            internal CryptoTransformAdaptor(Platform.ICryptoTransform transform)
            {
                Requires.NotNull(transform, "transform");
                this.transform = transform;
            }

            /// <inheritdoc />
            public bool CanReuseTransform
            {
                get { return this.transform.CanReuseTransform; }
            }

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks
            {
                get { return this.transform.CanTransformMultipleBlocks; }
            }

            /// <inheritdoc />
            public int InputBlockSize
            {
                get { return this.transform.InputBlockSize; }
            }

            /// <inheritdoc />
            public int OutputBlockSize
            {
                get { return this.transform.OutputBlockSize; }
            }

            /// <inheritdoc />
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                return this.transform.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            }

            /// <inheritdoc />
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                return this.transform.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            }

            /// <inheritdoc />
            public void Dispose()
            {
                this.transform.Dispose();
            }
        }
    }
}
