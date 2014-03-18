//-----------------------------------------------------------------------
// <copyright file="RsaCryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
//     Portions of this inspired by Patrick Hogan:
//         https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project/blob/master/Crypto/Crypto/Crypto/BDRSACryptor.m
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
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return KeyDataWithTag(GetPrivateKeyIdentifierWithTag(this.keyIdentifier)).ToArray();
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            RSAParameters parameters = Pkcs1KeyFormatter.ReadPkcs1PublicKey(KeyDataWithTag(GetPublicKeyIdentifierWithTag(this.keyIdentifier)).ToArray());
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    return Pkcs1KeyFormatter.WritePkcs1(parameters, includePrivateKey: false);
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return X509SubjectPublicKeyInfoFormatter.WriteX509SubjectPublicKeyInfo(parameters);
                default:
                    throw new NotSupportedException();
            }
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

        internal static RsaCryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType, AsymmetricAlgorithm algorithm)
        {
            RSAParameters parameters;
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    parameters = X509SubjectPublicKeyInfoFormatter.ReadX509SubjectPublicKeyInfo(keyBlob);
                    break;
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    parameters = Pkcs1KeyFormatter.ReadPkcs1PublicKey(keyBlob);
                    break;
                default:
                    throw new NotSupportedException();
            }

            // Inject the PKCS#1 public key into the KeyChain.
            string keyIdentifier = Guid.NewGuid().ToString();
            string publicKeyIdentifier = RsaCryptographicKey.GetPublicKeyIdentifierWithTag(keyIdentifier);
            var keyQueryDictionary = CreateKeyQueryDictionary(publicKeyIdentifier);
            keyQueryDictionary[KSec.ValueData] = NSData.FromArray(Pkcs1KeyFormatter.WritePkcs1(parameters, includePrivateKey: false));
            keyQueryDictionary[KSec.AttrKeyClass] = KSec.AttrKeyClassPublic;
            keyQueryDictionary[KSec.ReturnRef] = NSNumber.FromBoolean(true);
            IntPtr resultHandle;
            int status = SecItemAdd(keyQueryDictionary.Handle, out resultHandle);
            if (resultHandle != IntPtr.Zero)
            {
                var key = new SecKey(resultHandle, true);
                return new RsaCryptographicKey(key, keyIdentifier, algorithm);
            }
            else
            {
                throw new InvalidOperationException("SecItemAdd return " + status);
            }
        }

        internal static RsaCryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            RSAParameters parameters;
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    parameters = Pkcs1KeyFormatter.ReadPkcs1PrivateKey(keyBlob);
                    break;
                default:
                    throw new NotSupportedException();
            }

            string keyIdentifier = Guid.NewGuid().ToString();
            SecKey privateKey = ImportKey(parameters, GetPrivateKeyIdentifierWithTag(keyIdentifier));
            SecKey publicKey = ImportKey(parameters.PublicKeyFilter(), GetPublicKeyIdentifierWithTag(keyIdentifier));
            return new RsaCryptographicKey(publicKey, privateKey, keyIdentifier, algorithm);
        }

        private static SecKey ImportKey(RSAParameters parameters, string tag)
        {
            using (var keyQueryDictionary = CreateKeyQueryDictionary(tag))
            {
                byte[] pkcs1Key = Pkcs1KeyFormatter.WritePkcs1(parameters, parameters.D != null);
                keyQueryDictionary[KSec.ValueData] = NSData.FromArray(pkcs1Key);
                keyQueryDictionary[KSec.AttrKeyClass] = parameters.D != null ? KSec.AttrKeyClassPrivate : KSec.AttrKeyClassPublic;
                keyQueryDictionary[KSec.ReturnRef] = NSNumber.FromBoolean(true);
                IntPtr handle;
                int status = SecItemAdd(keyQueryDictionary.Handle, out handle);
                Verify.Operation(status == 0, "SecItemAdd returned {0}", status);
                return new SecKey(handle, true);
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

        [DllImport(Constants.SecurityLibrary)]
        private static extern int SecItemAdd(IntPtr query, out IntPtr result);

        private static NSMutableDictionary CreateKeyQueryDictionary(string tag)
        {
            var parameters = new NSMutableDictionary();
            parameters[KSec.Class] = KSec.ClassKey;
            parameters[KSec.AttrApplicationTag] = NSData.FromString(tag, NSStringEncoding.UTF8);
            parameters[KSec.AttrKeyType] = KSec.AttrKeyTypeRSA;
            parameters[KSec.AttrAccessible] = KSec.AttrAccessibleWhenUnlocked;
            return parameters;
        }

        internal static string GetPrivateKeyIdentifierWithTag(string tag)
        {
            return tag + ".privateKey";
        }

        internal static string GetPublicKeyIdentifierWithTag(string tag)
        {
            return tag + ".publicKey";
        }

        private static NSData KeyDataWithTag(string tag)
        {
            NSMutableDictionary queryKey = CreateKeyQueryDictionary(tag);
            queryKey[KSec.ReturnData] = NSNumber.FromBoolean(true);

            IntPtr typeRef;
            int code = SecItemCopyMatching(queryKey.Handle, out typeRef);
            var keyData = new NSData(typeRef);
            return keyData;
        }

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
