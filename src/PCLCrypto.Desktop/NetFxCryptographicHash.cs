//-----------------------------------------------------------------------
// <copyright file="NetFxCryptographicHash.cs" company="Andrew Arnott">
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
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="CryptographicHash"/> interface.
    /// </summary>
    internal abstract class NetFxCryptographicHash : CryptographicHash
    {
        /// <summary>
        /// A zero-length byte array.
        /// </summary>
        private static readonly byte[] EmptyBlock = new byte[0];

        /// <summary>
        /// The stream that we write to for incremental hashing.
        /// </summary>
        private Platform.CryptoStream stream;

        /// <summary>
        /// The platform-specific hash algorithm.
        /// </summary>
        private Platform.HashAlgorithm algorithm;

        /// <summary>
        /// A flag indicating whether this instance has been initialized.
        /// </summary>
        private bool initialized;

        /// <inheritdoc />
        public override void Append(byte[] data)
        {
            this.Initialize();
            this.stream.Write(data, 0, data.Length);
        }

        /// <inheritdoc />
        public override byte[] GetValueAndReset()
        {
            this.Initialize();
            this.stream.FlushFinalBlock();
            byte[] hash = this.algorithm.Hash;

            // Reset state on next invocation.
            this.initialized = false;

            return hash;
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            var disposable = this.algorithm as IDisposable;
            if (disposable != null)
            {
                disposable.Dispose();
                this.algorithm = null;
            }

            if (this.stream != null)
            {
                this.stream.Dispose();
                this.stream = null;
            }
        }

        /// <summary>
        /// Creates the hash algorithm.
        /// </summary>
        /// <returns>The hash algorithm.</returns>
        protected abstract Platform.HashAlgorithm CreateHashAlgorithm();

        /// <summary>
        /// Initializes for a new incremental hash.
        /// </summary>
        private void Initialize()
        {
            if (!this.initialized)
            {
                if (this.algorithm != null)
                {
                    if (this.algorithm.CanReuseTransform)
                    {
                        this.algorithm.Initialize();
                    }
                    else
                    {
                        var disposable = this.algorithm as IDisposable;
                        if (disposable != null)
                        {
                            disposable.Dispose();
                        }

                        this.algorithm = null;
                    }
                }

                if (this.algorithm == null)
                {
                    this.algorithm = this.CreateHashAlgorithm();
                }

                if (this.stream != null)
                {
                    this.stream.Dispose();
                }

                this.stream = new Platform.CryptoStream(Stream.Null, this.algorithm, Platform.CryptoStreamMode.Write);
                this.initialized = true;
            }
        }
    }
}
