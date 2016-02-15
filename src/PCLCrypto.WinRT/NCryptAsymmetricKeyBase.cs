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

    internal abstract class NCryptAsymmetricKeyBase : NCryptKeyBase
    {
        protected NCryptAsymmetricKeyBase(NCryptAsymmetricKeyProviderBase provider, SafeKeyHandle key, bool isPublicOnly)
            : base(key)
        {
            Requires.NotNull(provider, nameof(provider));

            this.Provider = provider;
            this.SignatureHashAlgorithm = this.SignatureHash.HasValue ? WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(this.SignatureHash.Value) : null;
            this.IsPublicOnly = isPublicOnly;
        }

        protected unsafe delegate void SignOrVerifyAction(void* paddingInfo, NCryptSignHashFlags flags);

        protected unsafe delegate byte[] EncryptOrDecryptFunction(void* paddingInfo, NCryptEncryptFlags flags);

        protected NCryptAsymmetricKeyProviderBase Provider { get; }

        protected AsymmetricEncryptionPadding? EncryptionPadding => this.Algorithm.GetEncryptionPadding();

        protected AsymmetricSignaturePadding? SignaturePadding => this.Algorithm.GetSignaturePadding();

        protected AsymmetricAlgorithm Algorithm => this.Provider.Algorithm;

        protected HashAlgorithm? SignatureHash => this.Algorithm.GetHashAlgorithm();

        /// <inheritdoc />
        protected override IHashAlgorithmProvider SignatureHashAlgorithm { get; }

        protected bool IsPublicOnly { get; }

        /// <inheritdoc />
        public override byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Verify.Operation(!this.IsPublicOnly, "Only public key is available.");
            try
            {
                byte[] nativeBlob;
                string nativeFormatString;
                CryptographicPrivateKeyBlobType nativeBlobType;
                if (this.Provider.NativePrivateKeyFormats.TryGetValue(blobType, out nativeFormatString))
                {
                    nativeBlobType = blobType;
                }
                else
                {
                    nativeBlobType = this.Provider.PreferredNativePrivateKeyFormat;
                    nativeFormatString = this.Provider.NativePrivateKeyFormats[nativeBlobType];
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
                byte[] nativeBlob = NCryptExportKey(this.Key, SafeKeyHandle.Null, this.Provider.NativePublicKeyFormatString, IntPtr.Zero).ToArray();
                byte[] formattedBlob = blobType == this.Provider.NativePublicKeyFormatEnum
                    ? nativeBlob
                    : KeyFormatter.GetFormatter(blobType).Write(KeyFormatter.GetFormatter(this.Provider.NativePublicKeyFormatEnum).Read(nativeBlob));
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
        protected internal override unsafe byte[] SignHash(byte[] data)
        {
            byte[] signature = null;
            this.SignOrVerify(
                (paddingInfo, flags) =>
                    signature = NCryptSignHash(this.Key, paddingInfo, data, flags).ToArray());
            return signature;
        }

        /// <inheritdoc />
        protected internal override unsafe bool VerifyHash(byte[] data, byte[] signature)
        {
            bool verified = false;
            this.SignOrVerify(
                (paddingInfo, flags) =>
                {
                    try
                    {
                        verified = NCryptVerifySignature(this.Key, paddingInfo, data, signature, flags);
                    }
                    catch (SecurityStatusException ex)
                    {
                        // Signatures with an unexpected size throw. But we should just return false.
                        if (ex.NativeErrorCode != SECURITY_STATUS.NTE_INVALID_PARAMETER)
                        {
                            throw;
                        }
                    }
                });
            return verified;
        }

        /// <inheritdoc />
        protected internal override unsafe byte[] Encrypt(byte[] data, byte[] iv)
        {
            Verify.Operation(iv == null, "IV not applicable for this key.");

            return this.EncryptOrDecrypt(
                (padding, flags) => NCryptEncrypt(this.Key, data, padding, flags).ToArray());
        }

        /// <inheritdoc />
        protected internal override unsafe byte[] Decrypt(byte[] data, byte[] iv)
        {
            Verify.Operation(iv == null, "IV not applicable for this key.");

            return this.EncryptOrDecrypt(
                (padding, flags) => NCryptDecrypt(this.Key, data, padding, flags).ToArray());
        }

        protected unsafe void SignOrVerify(SignOrVerifyAction action)
        {
            Requires.NotNull(action, nameof(action));

            if (this.SignaturePadding.Value == AsymmetricSignaturePadding.None)
            {
                action(null, NCryptSignHashFlags.None);
            }
            else
            {
                char[] hashAlgorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(this.SignatureHash.Value).ToCharArrayWithNullTerminator();
                fixed (char* hashAlgorithmNamePointer = &hashAlgorithmName[0])
                {
                    switch (this.SignaturePadding.Value)
                    {
                        case AsymmetricSignaturePadding.Pkcs1:
                            var pkcs1PaddingInfo = new BCrypt.BCRYPT_PKCS1_PADDING_INFO
                            {
                                pszAlgId = hashAlgorithmNamePointer,
                            };
                            action(&pkcs1PaddingInfo, NCryptSignHashFlags.BCRYPT_PAD_PKCS1);
                            break;
                        case AsymmetricSignaturePadding.Pss:
                            var pssPaddingInfo = new BCrypt.BCRYPT_PSS_PADDING_INFO
                            {
                                pszAlgId = hashAlgorithmNamePointer,
                                cbSalt = hashAlgorithmName.Length,
                            };
                            action(&pssPaddingInfo, NCryptSignHashFlags.BCRYPT_PAD_PSS);
                            break;
                        default:
                            throw new NotImplementedException();
                    }
                }
            }
        }

        protected unsafe byte[] EncryptOrDecrypt(EncryptOrDecryptFunction cipherFunction)
        {
            Requires.NotNull(cipherFunction, nameof(cipherFunction));

            if (this.EncryptionPadding.Value == AsymmetricEncryptionPadding.None)
            {
                return cipherFunction(null, NCryptEncryptFlags.NCRYPT_NO_PADDING_FLAG);
            }

            switch (this.EncryptionPadding.Value)
            {
                case AsymmetricEncryptionPadding.Pkcs1:
                    return cipherFunction(null, NCryptEncryptFlags.NCRYPT_PAD_PKCS1_FLAG);
                case AsymmetricEncryptionPadding.Oaep:
                    fixed (char* hashAlgorithmNamePointer = &HashAlgorithmProviderFactory.GetHashAlgorithmName(this.SignatureHash.Value).ToCharArrayWithNullTerminator()[0])
                    {
                        var paddingInfo = new BCrypt.BCRYPT_OAEP_PADDING_INFO
                        {
                            pszAlgId = hashAlgorithmNamePointer,
                            pbLabel = null,
                            cbLabel = 0,
                        };
                        return cipherFunction(&paddingInfo, NCryptEncryptFlags.NCRYPT_PAD_OAEP_FLAG);
                    }

                default:
                    throw new NotImplementedException();
            }
        }
    }
}
