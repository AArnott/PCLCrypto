//-----------------------------------------------------------------------
// <copyright file="CryptographicHash.cs" company="Andrew Arnott">
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
    /// A .NET Framework implementation of the <see cref="ICryptographicHash"/> interface.
    /// </summary>
    internal class CryptographicHash : ICryptographicHash
    {
        /// <summary>
        /// A zero-length byte array.
        /// </summary>
        private static readonly byte[] EmptyBlock = new byte[0];

        /// <summary>
        /// The algorithm enum.
        /// </summary>
        private HashAlgorithm pclAlgorithm;

        /// <summary>
        /// The platform-specific hash algorithm.
        /// </summary>
        private Platform.HashAlgorithm algorithm;

        /// <summary>
        /// The stream that we write to for incremental hashing.
        /// </summary>
        private Platform.CryptoStream stream;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicHash" /> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal CryptographicHash(HashAlgorithm algorithm)
        {
            this.pclAlgorithm = algorithm;
            this.Initialize();
        }

        /// <inheritdoc />
        public void Append(byte[] data)
        {
            this.stream.Write(data, 0, data.Length);
        }

        /// <inheritdoc />
        public byte[] GetValueAndReset()
        {
            this.stream.FlushFinalBlock();
            byte[] hash = this.algorithm.Hash;

            // Reset state.
            this.Initialize();

            return hash;
        }

        /// <summary>
        /// Initializes for a new incremental hash.
        /// </summary>
        private void Initialize()
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
                this.algorithm = HashAlgorithmProvider.CreateHashAlgorithm(this.pclAlgorithm);
            }

            if (this.stream != null)
            {
                this.stream.Dispose();
            }

            this.stream = new Platform.CryptoStream(Stream.Null, this.algorithm, Platform.CryptoStreamMode.Write);
        }
    }
}
