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
    using static PInvoke.BCrypt;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// The base class for BCrypt implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal abstract class BCryptCryptographicKeyBase : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BCryptCryptographicKeyBase" /> class.
        /// </summary>
        internal BCryptCryptographicKeyBase()
        {
        }

        /// <inheritdoc />
        public int KeySize => BCryptGetProperty<int>(this.Key, PropertyNames.BCRYPT_KEY_LENGTH);

        /// <summary>
        /// Gets the handle to the BCrypt cryptographic key for purposes of key export.
        /// </summary>
        protected abstract SafeKeyHandle Key { get; }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            try
            {
                return BCryptExportKey(this.Key, SafeKeyHandle.Null, this.GetBCryptBlobType(blobType)).ToArray();
            }
            catch (Win32Exception ex)
            {
                if ((Win32ErrorCode)ex.NativeErrorCode == Win32ErrorCode.ERROR_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            try
            {
                return BCryptExportKey(this.Key, SafeKeyHandle.Null, this.GetBCryptBlobType(blobType)).ToArray();
            }
            catch (NTStatusException ex)
            {
                if (ex.StatusCode.Value == NTStatus.Code.STATUS_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

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

        protected abstract string GetBCryptBlobType(CryptographicPrivateKeyBlobType blobType);

        protected abstract string GetBCryptBlobType(CryptographicPublicKeyBlobType blobType);
    }
}
