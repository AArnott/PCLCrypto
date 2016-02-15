// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Formatters;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// An RSA asymmetric cryptographic key backed by the Win32 crypto library.
    /// </summary>
    internal class AsymmetricRsaCryptographicKey : NCryptCryptographicAsymmetricKeyBase, ICryptographicKey
    {
        private readonly bool publicKeyOnly;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricRsaCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The BCrypt cryptographic key handle.</param>
        /// <param name="algorithm">The asymmetric algorithm used by this instance.</param>
        internal AsymmetricRsaCryptographicKey(SafeKeyHandle key, AsymmetricAlgorithm algorithm, bool publicKeyOnly)
            : base(key, algorithm)
        {
            this.publicKeyOnly = publicKeyOnly;
        }

        /// <inheritdoc />
        public override byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            Verify.Operation(!this.publicKeyOnly, "Only public key is available.");
            try
            {
                byte[] nativeBlob;
                string nativeFormatString;
                CryptographicPrivateKeyBlobType nativeBlobType;
                if (AsymmetricKeyRsaAlgorithmProvider.NativePrivateKeyFormats.TryGetValue(blobType, out nativeFormatString))
                {
                    nativeBlobType = blobType;
                }
                else
                {
                    nativeBlobType = AsymmetricKeyRsaAlgorithmProvider.PreferredNativePrivateKeyFormat;
                    nativeFormatString = AsymmetricKeyRsaAlgorithmProvider.NativePrivateKeyFormats[nativeBlobType];
                }

                nativeBlob = NCryptExportKey(this.Key, SafeKeyHandle.Null, nativeFormatString, IntPtr.Zero).ToArray();

                byte[] formattedBlob;
                if (nativeBlobType != blobType)
                {
                    var parameters = KeyFormatter.GetFormatter(nativeBlobType).Read(nativeBlob);
                    formattedBlob = KeyFormatter.GetFormatter(blobType).Write(parameters);
                }
                else
                {
                    formattedBlob = nativeBlob;
                }

                return formattedBlob;
            }
            catch (SecurityStatusException ex)
            {
                if (ex.NativeErrorCode == SECURITY_STATUS.NTE_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        /// <inheritdoc />
        public override byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            try
            {
                byte[] nativeBlob = NCryptExportKey(this.Key, SafeKeyHandle.Null, AsymmetricKeyRsaAlgorithmProvider.NativePublicKeyFormatString, IntPtr.Zero).ToArray();
                byte[] formattedBlob = blobType == AsymmetricKeyRsaAlgorithmProvider.NativePublicKeyFormatEnum
                    ? nativeBlob
                    : KeyFormatter.GetFormatter(blobType).Write(KeyFormatter.GetFormatter(AsymmetricKeyRsaAlgorithmProvider.NativePublicKeyFormatEnum).Read(nativeBlob));
                return formattedBlob;
            }
            catch (SecurityStatusException ex)
            {
                if (ex.NativeErrorCode == SECURITY_STATUS.NTE_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }
    }
}
