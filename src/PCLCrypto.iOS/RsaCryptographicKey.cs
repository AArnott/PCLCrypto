//-----------------------------------------------------------------------
// <copyright file="RsaCryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Mono.Security.Cryptography;
    using MonoTouch;
    using MonoTouch.CoreFoundation;
    using MonoTouch.Foundation;
    using MonoTouch.ObjCRuntime;
    using MonoTouch.Security;
    using PCLCrypto.Formatters;
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
        /// The platform private key.
        /// </summary>
        private readonly SecKey privateKey;

        /// <summary>
        /// The tag that may be used to query the keychain for the key.
        /// </summary>
        private readonly string keyIdentifier;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="keyIdentifier">The key identifier that may be used to query the keychain.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, string keyIdentifier, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");

            this.publicKey = publicKey;
            this.keyIdentifier = keyIdentifier;
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="keyIdentifier">The key identifier that may be used to query the keychain.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, SecKey privateKey, string keyIdentifier, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");
            Requires.NotNull(privateKey, "privateKey");

            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.keyIdentifier = keyIdentifier;
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
            byte[] keyData = KeyDataWithTag(GetPrivateKeyIdentifierWithTag(this.keyIdentifier)).ToArray();
            var parameters = KeyFormatter.Pkcs1.Read(keyData);

            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return KeyFormatter.Pkcs1.Write(parameters, true);
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    var rsa = new RSACryptoServiceProvider();
                    rsa.ImportParameters(parameters);

                    return rsa.ExportCspBlob(true);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            RSAParameters parameters = KeyFormatter.Pkcs1.Read(KeyDataWithTag(GetPublicKeyIdentifierWithTag(this.keyIdentifier)).ToArray());
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    return KeyFormatter.Pkcs1.Write(parameters, includePrivateKey: false);
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return KeyFormatter.X509SubjectPublicKeyInfo.Write(parameters, includePrivateKey: false);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Returns a key identifier specifically for private keys.
        /// </summary>
        /// <param name="tag">The generic private/public key identifier.</param>
        /// <returns>The specific private key identifier.</returns>
        internal static string GetPrivateKeyIdentifierWithTag(string tag)
        {
            return tag + ".privateKey";
        }

        /// <summary>
        /// Returns a key identifier specifically for public keys.
        /// </summary>
        /// <param name="tag">The generic private/public key identifier.</param>
        /// <returns>The specific public key identifier.</returns>
        internal static string GetPublicKeyIdentifierWithTag(string tag)
        {
            return tag + ".publicKey";
        }

        [DllImport(Constants.SecurityLibrary)]
        internal static extern int SecItemAdd(IntPtr query, out IntPtr result);

        /// <summary>
        /// Initializes a dictionary used to query for keys.
        /// </summary>
        /// <param name="tag">The tag of the key to be accessed.</param>
        /// <returns>The query dictionary.</returns>
        internal static NSMutableDictionary CreateKeyQueryDictionary(string tag)
        {
            var parameters = new NSMutableDictionary();
            parameters[KSec.Class] = KSec.ClassKey;
            parameters[KSec.AttrApplicationTag] = NSData.FromString(tag, NSStringEncoding.UTF8);
            parameters[KSec.AttrKeyType] = KSec.AttrKeyTypeRSA;
            parameters[KSec.AttrAccessible] = KSec.AttrAccessibleWhenUnlocked;
            return parameters;
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            using (var hasher = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                byte[] hash = hasher.ComputeHash(data);
                return this.SignHash(hash);
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var hasher = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                byte[] hash = hasher.ComputeHash(data);
                return this.VerifyHash(hash, signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            byte[] signature = new byte[this.privateKey.BlockSize];

            GCHandle dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            GCHandle signatureHandle = GCHandle.Alloc(signature, GCHandleType.Pinned);
            try
            {
                int signatureLength = signature.Length;
                var padding = GetPadding(this.Algorithm);
                SecStatusCode code = SecKeyRawSign(
                     this.privateKey.Handle,
                     padding,
                     dataHandle.AddrOfPinnedObject(),
                     data.Length,
                     signatureHandle.AddrOfPinnedObject(),
                     ref signatureLength);

                Verify.Operation(code == SecStatusCode.Success, "status was " + code);
                TrimBuffer(ref signature, signatureLength, secureClearOldBuffer: false);
            }
            finally
            {
                signatureHandle.Free();
                dataHandle.Free();
            }

            // TODO: Do we need to do any work on the returned signature so that it includes
            // the proper OID header?
            return signature;
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            SecStatusCode code = this.publicKey.RawVerify(GetPadding(this.Algorithm), data, signature);
            return code == SecStatusCode.Success;
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

        [DllImport(Constants.SecurityLibrary)]
        private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

        /// <summary>
        /// Gets thee PKCS#1 key data for a key in the key chain.
        /// </summary>
        /// <param name="tag">The unique tag for the key to retrieve data for.</param>
        /// <returns>The raw key data.</returns>
        private static NSData KeyDataWithTag(string tag)
        {
            NSMutableDictionary queryKey = CreateKeyQueryDictionary(tag);
            queryKey[KSec.ReturnData] = NSNumber.FromBoolean(true);

            IntPtr typeRef;
            int code = SecItemCopyMatching(queryKey.Handle, out typeRef);
            var keyData = new NSData(typeRef);
            return keyData;
        }

        /// <summary>
        /// Obtains a reference to an iOS security key given its identifying tag.
        /// </summary>
        /// <param name="tag">The tag of the key in the keychain.</param>
        /// <returns>The security key.</returns>
        private static SecKey KeyRefWithTag(string tag)
        {
            NSMutableDictionary queryKey = CreateKeyQueryDictionary(tag);
            queryKey[KSec.ReturnRef] = NSNumber.FromBoolean(true);

            IntPtr typeRef;
            int code = SecItemCopyMatching(queryKey.Handle, out typeRef);
            var keyRef = new SecKey(typeRef, owns: true);
            return keyRef;
        }
    }
}
