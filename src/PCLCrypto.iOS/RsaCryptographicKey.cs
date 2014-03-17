//-----------------------------------------------------------------------
// <copyright file="RsaCryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using MonoTouch;
    using MonoTouch.CoreFoundation;
    using MonoTouch.Foundation;
    using MonoTouch.ObjCRuntime;
    using MonoTouch.Security;
    using Validation;

    /// <summary>
    /// The iOS implementation of the <see cref="ICryptographicKey"/> interface
    /// for RSA keys.
    /// </summary>
    internal class RsaCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The platform public key.
        /// </summary>
        private readonly SecKey publicKey;

        /// <summary>
        /// The tag that may be used to query the keychain for the public key.
        /// </summary>
        private readonly string publicKeyTag;

        /// <summary>
        /// The platform private key.
        /// </summary>
        private readonly SecKey privateKey;

        /// <summary>
        /// The tag that may be used to query the keychain for the private key.
        /// </summary>
        private readonly string privateKeyTag;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="publicKeyTag">The tag that may be used to query the keychain for the public key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, string publicKeyTag, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");

            this.publicKey = publicKey;
            this.publicKeyTag = publicKeyTag;
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="publicKeyTag">The tag that may be used to query the keychain for the public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="privateKeyTag">The tag that may be used to query the keychain for the private key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, string publicKeyTag, SecKey privateKey, string privateKeyTag, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");
            Requires.NotNull(privateKey, "privateKey");

            this.publicKey = publicKey;
            this.publicKeyTag = publicKeyTag;
            this.privateKey = privateKey;
            this.privateKeyTag = privateKeyTag;
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.publicKey.BlockSize * 8; }
        }

        /// <summary>
        /// Gets the algorithm to use with this key.
        /// </summary>
        internal AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                ////return this.key.ExportCspBlob(includePrivateParameters: true);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                ////return this.key.ExportCspBlob(includePrivateParameters: false);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            byte[] signature = new byte[this.privateKey.BlockSize];
            GCHandle dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            GCHandle sigHandle = GCHandle.Alloc(signature, GCHandleType.Pinned);
            try
            {
                int signatureLength = signature.Length;
                SecStatusCode code = SecKeyRawSign(this.privateKey.Handle, GetPadding(this.Algorithm), dataHandle.AddrOfPinnedObject(), data.Length, sigHandle.AddrOfPinnedObject(), ref signatureLength);
                Verify.Operation(code == SecStatusCode.Success, "status was " + code);
                TrimBuffer(ref signature, signatureLength, secureClearOldBuffer: false);
                return signature;
            }
            finally
            {
                dataHandle.Free();
                sigHandle.Free();
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            SecStatusCode code = this.publicKey.RawVerify(GetPadding(this.Algorithm), data, signature);
            return code == SecStatusCode.Success;
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            byte[] cipherText;
            var code = this.publicKey.Encrypt(GetPadding(this.Algorithm), data, out cipherText);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);
            return cipherText;
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            // Initialize a plaintext buffer that is at least as large
            // as the plaintext could possibly be, which is as large as the
            // ciphertext is. Note the resulting plaintext could be smaller
            // as padding may be included in the ciphertext.
            byte[] plainText = new byte[data.Length];

            // WORKAROUND: Xamarin.iOS interop API doesn't allow us to determine the
            // actual length of the plaintext after decryption. Padding causes an
            // unpredictable plaintext length to be returned and we rely on the
            // SecKeyDecrypt API's output plainTextLen parameter to tell us, but
            // Xamarin.iOS doesn't hand this back to us. So we use our own P/Invoke method instead.
            GCHandle cipherTextHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            GCHandle plainTextHandle = GCHandle.Alloc(plainText, GCHandleType.Pinned);
            try
            {
                int plainTextLength = plainText.Length;
                SecStatusCode code = SecKeyDecrypt(this.privateKey.Handle, GetPadding(this.Algorithm), cipherTextHandle.AddrOfPinnedObject(), data.Length, plainTextHandle.AddrOfPinnedObject(), ref plainTextLength);
                Verify.Operation(code == SecStatusCode.Success, "status was " + code);
                TrimBuffer(ref plainText, plainTextLength, secureClearOldBuffer: true);

                return plainText;
            }
            finally
            {
                cipherTextHandle.Free();
                plainTextHandle.Free();
            }
        }

        /// <summary>
        /// Resizes a buffer to match the prescribed size.
        /// </summary>
        /// <param name="buffer">The buffer to be resized.</param>
        /// <param name="bufferLength">Desired length of the buffer.</param>
        /// <param name="secureClearOldBuffer">if set to <c>true</c>, the old buffer is cleared of its contents in the event that it is discarded.</param>
        private static void TrimBuffer(ref byte[] buffer, int bufferLength, bool secureClearOldBuffer)
        {
            Requires.NotNull(buffer, "buffer");

            if (bufferLength < buffer.Length)
            {
                // Reallocate the buffer so we can return a buffer of the appropriate size to the caller.
                byte[] smallerBuffer = new byte[bufferLength];
                Array.Copy(buffer, smallerBuffer, bufferLength);

                if (secureClearOldBuffer)
                {
                    // A one more piece of security, clear out the original buffer we won't be returning to the caller.
                    Array.Clear(buffer, 0, buffer.Length);
                }

                buffer = smallerBuffer;
            }
        }

        /// <summary>
        /// Gets the iOS padding algorithm for a given asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The asymmetric algorithm.</param>
        /// <returns>The iOS platform padding enum.</returns>
        private static SecPadding GetPadding(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    return SecPadding.OAEP;
                case AsymmetricAlgorithm.RsaPkcs1:
                    return SecPadding.PKCS1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                    return SecPadding.PKCS1SHA1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                    return SecPadding.PKCS1SHA256;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                    return SecPadding.PKCS1SHA384;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return SecPadding.PKCS1SHA512;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Decrypts a ciphertext that was asymmetrically encrypted.
        /// </summary>
        /// <param name="handle">The <see cref="SecKey.Handle"/> value from the private key to use in decryption.</param>
        /// <param name="padding">The padding algorithm applied during encryption.</param>
        /// <param name="cipherText">A pointer to the ciphertext to decrypt.</param>
        /// <param name="cipherTextLen">The length of the ciphertext to decrypt.</param>
        /// <param name="plainText">The buffer to receive the plaintext. This should be at least as large as the <paramref name="cipherText"/> buffer.</param>
        /// <param name="plainTextLen">Indicates the length of the <paramref name="plainText"/> buffer. Upon return, this value is set to the length of the actual decrypted bytes.</param>
        /// <returns>A value indicating the successful or failure result of the operation.</returns>
        [DllImport(Constants.SecurityLibrary)]
        private static extern SecStatusCode SecKeyDecrypt(IntPtr handle, SecPadding padding, IntPtr cipherText, int cipherTextLen, IntPtr plainText, ref int plainTextLen);

        [DllImport(Constants.SecurityLibrary)]
        private static extern SecStatusCode SecKeyRawSign(IntPtr handle, SecPadding padding, IntPtr dataToSign, int dataToSignLen, IntPtr sig, ref int sigLen);
    }
}
