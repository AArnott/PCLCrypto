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

    /// <summary>
    /// Base class for implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal abstract class CryptographicKey : IDisposable
    {
        /// <summary>
        /// Gets the hash algorithm to use for signatures. May be null.
        /// </summary>
        protected virtual IHashAlgorithmProvider SignatureHashAlgorithm
        {
            get { throw new NotSupportedException(); }
        }

        /// <summary>
        /// Gets the hash algorithm to use for signatures, or throws an exception if null.
        /// </summary>
        protected IHashAlgorithmProvider SignatureHashAlgorithmOrThrow
        {
            get
            {
                var hashAlgorithm = this.SignatureHashAlgorithm;
                Verify.Operation(hashAlgorithm != null, "No hash function has been defined for this key.");
                return hashAlgorithm;
            }
        }

        /// <summary>
        /// Disposes managed and native resources associated with this instance.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Signs data with this key.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The signature.</returns>
        protected internal virtual byte[] Sign(byte[] data)
        {
            return this.SignHash(this.SignatureHashAlgorithmOrThrow.HashData(data));
        }

        /// <summary>
        /// Verifies the signature of data with this key.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid.
        /// </returns>
        protected internal virtual bool VerifySignature(byte[] data, byte[] signature)
        {
            return this.VerifyHash(this.SignatureHashAlgorithmOrThrow.HashData(data), signature);
        }

        /// <summary>
        /// Signs data with this key.
        /// </summary>
        /// <param name="data">The hash of the data.</param>
        /// <returns>The signature.</returns>
        protected internal virtual byte[] SignHash(byte[] data)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Verifies the signature of a hash of data with this key.
        /// </summary>
        /// <param name="data">The hash of the data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid.
        /// </returns>
        protected internal virtual bool VerifyHash(byte[] data, byte[] signature)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The plaintext.</param>
        /// <param name="iv">The initialization vector. Should be <c>null</c> for asymmetric algorithms.</param>
        /// <returns>The ciphertext.</returns>
        protected internal virtual byte[] Encrypt(byte[] data, byte[] iv)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="data">The ciphertext.</param>
        /// <param name="iv">The initialization vector. Should be <c>null</c> for asymmetric algorithms.</param>
        /// <returns>The plaintext.</returns>
        protected internal virtual byte[] Decrypt(byte[] data, byte[] iv)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Creates a crypto transform to encrypt a stream.
        /// </summary>
        /// <param name="iv">The initialization vector. Should be <c>null</c> for asymmetric algorithms.</param>
        /// <returns>The ciphertext.</returns>
        protected internal virtual ICryptoTransform CreateEncryptor(byte[] iv)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Creates a crypto transform to decrypt a stream.
        /// </summary>
        /// <param name="iv">The initialization vector. Should be <c>null</c> for asymmetric algorithms.</param>
        /// <returns>The plaintext.</returns>
        protected internal virtual ICryptoTransform CreateDecryptor(byte[] iv)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Derives a key from another key by using a key derivation function.
        /// </summary>
        /// <param name="parameters">Derivation parameters. The parameters vary depending on the type of KDF algorithm
        /// used.</param>
        /// <param name="desiredKeySize">Requested size, in bytes, of the derived key.</param>
        /// <returns>
        /// Buffer that contains the derived key.
        /// </returns>
        protected internal virtual byte[] DeriveKeyMaterial(IKeyDerivationParameters parameters, int desiredKeySize)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Disposes managed and native resources associated with this instance.
        /// </summary>
        /// <param name="disposing"><c>true</c> if this object is being disposed; <c>false</c> if it is being finalized.</param>
        protected virtual void Dispose(bool disposing)
        {
        }
    }
}
