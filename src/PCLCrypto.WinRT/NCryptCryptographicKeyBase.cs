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
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// The base class for NCrypt implementations of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal abstract class NCryptCryptographicKeyBase : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NCryptCryptographicKeyBase" /> class.
        /// </summary>
        internal NCryptCryptographicKeyBase()
        {
        }

        /// <inheritdoc />
        public int KeySize => NCryptGetProperty<int>(this.Key, KeyStoragePropertyIdentifiers.NCRYPT_LENGTH_PROPERTY);

        /// <summary>
        /// Gets the handle to the NCrypt cryptographic key for purposes of key export.
        /// </summary>
        protected abstract SafeKeyHandle Key { get; }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            try
            {
                return NCryptExportKey(this.Key, SafeKeyHandle.Null, this.GetNCryptBlobType(blobType), IntPtr.Zero).ToArray();
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
                return NCryptExportKey(this.Key, SafeKeyHandle.Null, this.GetNCryptBlobType(blobType), IntPtr.Zero).ToArray();
            }
            catch (NTStatusException ex)
            {
                if (ex.NativeErrorCode.Value == NTSTATUS.Code.STATUS_NOT_SUPPORTED)
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

        protected abstract string GetNCryptBlobType(CryptographicPrivateKeyBlobType blobType);

        protected abstract string GetNCryptBlobType(CryptographicPublicKeyBlobType blobType);
    }
}
