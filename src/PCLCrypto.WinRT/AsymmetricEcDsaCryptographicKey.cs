// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// A cryptographic key for ECDSA operations.
    /// </summary>
    internal class AsymmetricEcDsaCryptographicKey : NCryptAsymmetricKeyBase
    {
        internal AsymmetricEcDsaCryptographicKey(SafeKeyHandle key, AsymmetricAlgorithm algorithm)
            : base(key, algorithm)
        {
        }

        /// <inheritdoc />
        public override byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            Requires.Argument(blobType == AsymmetricKeyECDsaAlgorithmProvider.NativePrivateKeyFormatEnum, nameof(blobType), "Not a supported blob type.");

            try
            {
                return NCryptExportKey(
                    this.Key,
                    SafeKeyHandle.Null,
                    AsymmetricKeyECDsaAlgorithmProvider.NativePrivateKeyFormatString,
                    IntPtr.Zero).ToArray();
            }
            catch (NTStatusException ex)
            {
                if (ex.NativeErrorCode == NTSTATUS.Code.STATUS_NOT_SUPPORTED)
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        /// <inheritdoc />
        public override byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            Requires.Argument(blobType == AsymmetricKeyECDsaAlgorithmProvider.NativePublicKeyFormatEnum, nameof(blobType), "Not a supported blob type.");

            try
            {
                return NCryptExportKey(
                    this.Key,
                    SafeKeyHandle.Null,
                    AsymmetricKeyECDsaAlgorithmProvider.NativePublicKeyFormatString,
                    IntPtr.Zero).ToArray();
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
    }
}
