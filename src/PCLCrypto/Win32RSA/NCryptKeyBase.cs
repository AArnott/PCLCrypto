// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// The base class for NCrypt implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal abstract class NCryptKeyBase : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NCryptKeyBase" /> class.
        /// </summary>
        /// <param name="key">The native NCrypt key that this instance represents.</param>
        internal NCryptKeyBase(SafeKeyHandle key)
        {
            Requires.NotNull(key, nameof(key));
            this.Key = key;
        }

        /// <inheritdoc />
        public int KeySize => NCryptGetProperty<int>(this.Key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTH_PROPERTY);

        /// <summary>
        /// Gets the handle to the NCrypt cryptographic key for purposes of key export.
        /// </summary>
        protected SafeKeyHandle Key { get; }

        /// <inheritdoc />
        public abstract byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo);

        /// <inheritdoc />
        public abstract byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);

        /// <summary>
        /// Disposes of managed and native resources of this object.
        /// </summary>
        /// <param name="disposing"><c>true</c> if this object is being disposed of; <c>false</c> if being finalized.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.Key.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
