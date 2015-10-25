// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Base class for implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal class CryptographicKey
    {
        /// <summary>
        /// Signs data with this key.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The signature.</returns>
        protected internal virtual byte[] Sign(byte[] data)
        {
            throw new NotSupportedException();
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
            throw new NotSupportedException();
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
    }
}
