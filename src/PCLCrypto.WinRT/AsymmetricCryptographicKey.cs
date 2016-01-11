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
    using static PInvoke.BCrypt;

    /// <summary>
    /// An asymmetric cryptographic key backed by the Win32 BCrypt library.
    /// </summary>
    internal class AsymmetricCryptographicKey : BCryptCryptographicKeyBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The BCrypt cryptographic key handle.</param>
        /// <param name="algorithm">The asymmetric algorithm used by this instance.</param>
        internal AsymmetricCryptographicKey(SafeKeyHandle key, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(key, nameof(key));

            this.Key = key;
            this.Algorithm = algorithm;
            this.SignatureHashAlgorithm = this.SignatureHash.HasValue ? WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(this.SignatureHash.Value) : null;
        }

        protected unsafe delegate void SignOrVerifyAction(void* paddingInfo, BCryptSignHashFlags flags);

        protected unsafe delegate byte[] EncryptOrDecryptFunction(void* paddingInfo, BCryptEncryptFlags flags);

        /// <inheritdoc />
        protected override SafeKeyHandle Key { get; }

        /// <inheritdoc />
        protected override IHashAlgorithmProvider SignatureHashAlgorithm { get; }

        protected AsymmetricAlgorithm Algorithm { get; }

        protected AsymmetricEncryptionPadding? EncryptionPadding => this.Algorithm.GetEncryptionPadding();

        protected AsymmetricSignaturePadding? SignaturePadding => this.Algorithm.GetSignaturePadding();

        protected HashAlgorithm? SignatureHash => this.Algorithm.GetHashAlgorithm();

        /// <inheritdoc />
        protected internal override unsafe byte[] SignHash(byte[] data)
        {
            byte[] signature = null;
            this.SignOrVerify(
                (paddingInfo, flags) =>
                {
                    signature = BCryptSignHash(this.Key, data, paddingInfo, flags).ToArray();
                });
            return signature;
        }

        /// <inheritdoc />
        protected internal override unsafe bool VerifyHash(byte[] data, byte[] signature)
        {
            bool verified = false;
            this.SignOrVerify(
                (paddingInfo, flags) =>
                {
                    NTStatus status = BCryptVerifySignature(this.Key, paddingInfo, data, data.Length, signature, signature.Length, flags);
                    verified = status == NTStatus.STATUS_SUCCESS;

                    // Throw on errors except the invalid signature status, since we return false in that case.
                    if (status != NTStatus.STATUS_INVALID_SIGNATURE)
                    {
                        status.ThrowOnError();
                    }
                });
            return verified;
        }

        /// <inheritdoc />
        protected internal override unsafe byte[] Encrypt(byte[] data, byte[] iv)
        {
            return this.EncryptOrDecrypt(
                (padding, flags) => BCryptEncrypt(this.Key, data, padding, iv, flags).ToArray());
        }

        /// <inheritdoc />
        protected internal override unsafe byte[] Decrypt(byte[] data, byte[] iv)
        {
            return this.EncryptOrDecrypt(
                (padding, flags) => BCryptDecrypt(this.Key, data, padding, iv, flags).ToArray());
        }

        protected unsafe void SignOrVerify(SignOrVerifyAction action)
        {
            Requires.NotNull(action, nameof(action));

            if (this.SignaturePadding.Value == AsymmetricSignaturePadding.None)
            {
                action(null, BCryptSignHashFlags.None);
            }
            else
            {
                char[] hashAlgorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(this.SignatureHash.Value).ToCharArrayWithNullTerminator();
                fixed (char* hashAlgorithmNamePointer = &hashAlgorithmName[0])
                {
                    switch (this.SignaturePadding.Value)
                    {
                        case AsymmetricSignaturePadding.Pkcs1:
                            var pkcs1PaddingInfo = new BCRYPT_PKCS1_PADDING_INFO
                            {
                                pszAlgId = hashAlgorithmNamePointer,
                            };
                            action(&pkcs1PaddingInfo, BCryptSignHashFlags.BCRYPT_PAD_PKCS1);
                            break;
                        case AsymmetricSignaturePadding.Pss:
                            var pssPaddingInfo = new BCRYPT_PSS_PADDING_INFO
                            {
                                pszAlgId = hashAlgorithmNamePointer,
                                cbSalt = hashAlgorithmName.Length,
                            };
                            action(&pssPaddingInfo, BCryptSignHashFlags.BCRYPT_PAD_PSS);
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
                return cipherFunction(null, BCryptEncryptFlags.BCRYPT_PAD_NONE);
            }

            switch (this.EncryptionPadding.Value)
            {
                case AsymmetricEncryptionPadding.Pkcs1:
                    return cipherFunction(null, BCryptEncryptFlags.BCRYPT_PAD_PKCS1);
                case AsymmetricEncryptionPadding.Oaep:
                    fixed (char* hashAlgorithmNamePointer = &HashAlgorithmProviderFactory.GetHashAlgorithmName(this.SignatureHash.Value).ToCharArrayWithNullTerminator()[0])
                    {
                        var paddingInfo = new BCRYPT_OAEP_PADDING_INFO
                        {
                            pszAlgId = hashAlgorithmNamePointer,
                            pbLabel = null,
                            cbLabel = 0,
                        };
                        return cipherFunction(&paddingInfo, BCryptEncryptFlags.BCRYPT_PAD_OAEP);
                    }

                default:
                    throw new NotImplementedException();
            }
        }

        protected override string GetBCryptBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            return AsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType);
        }

        protected override string GetBCryptBlobType(CryptographicPublicKeyBlobType blobType)
        {
            return AsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType, this.Algorithm.GetName());
        }
    }
}
