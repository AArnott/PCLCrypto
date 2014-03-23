//-----------------------------------------------------------------------
// <copyright file="RsaAsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Mono.Security.Cryptography;
    using MonoTouch;
    using MonoTouch.Foundation;
    using MonoTouch.ObjCRuntime;
    using MonoTouch.Security;
    using PCLCrypto.Formatters;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of RSA.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            string keyIdentifier = Guid.NewGuid().ToString();
            string publicKeyIdentifier = RsaCryptographicKey.GetPublicKeyIdentifierWithTag(keyIdentifier);
            string privateKeyIdentifier = RsaCryptographicKey.GetPrivateKeyIdentifierWithTag(keyIdentifier);

            // Configure parameters for the joint keypair.
            var keyPairAttr = new NSMutableDictionary();
            keyPairAttr[KSec.AttrKeyType] = KSec.AttrKeyTypeRSA;
            keyPairAttr[KSec.AttrKeySizeInBits] = NSNumber.FromInt32(keySize);

            // Configure parameters for the private key
            var privateKeyAttr = new NSMutableDictionary();
            privateKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            privateKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(privateKeyIdentifier, NSStringEncoding.UTF8);

            // Configure parameters for the public key
            var publicKeyAttr = new NSMutableDictionary();
            publicKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            publicKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(publicKeyIdentifier, NSStringEncoding.UTF8);

            // Parent the individual key parameters to the keypair one.
            keyPairAttr[KSec.PublicKeyAttrs] = publicKeyAttr;
            keyPairAttr[KSec.PrivateKeyAttrs] = privateKeyAttr;

            // Generate the RSA key.
            SecKey publicKey, privateKey;
            SecStatusCode code = SecKey.GenerateKeyPair(keyPairAttr, out publicKey, out privateKey);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);

            return new RsaCryptographicKey(publicKey, privateKey, keyIdentifier, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            RSAParameters parameters;
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    parameters = KeyFormatter.Pkcs1.Read(keyBlob);
                    break;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    var rsa = new RSACryptoServiceProvider();
                    rsa.ImportCspBlob(keyBlob);
                    parameters = rsa.ExportParameters(true);
                    break;
                default:
                    throw new NotSupportedException();
            }

            string keyIdentifier = Guid.NewGuid().ToString();
            SecKey privateKey = ImportKey(parameters, RsaCryptographicKey.GetPrivateKeyIdentifierWithTag(keyIdentifier));
            SecKey publicKey = ImportKey(KeyFormatter.PublicKeyFilter(parameters), RsaCryptographicKey.GetPublicKeyIdentifierWithTag(keyIdentifier));
            return new RsaCryptographicKey(publicKey, privateKey, keyIdentifier, this.Algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            RSAParameters parameters;
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    parameters = KeyFormatter.X509SubjectPublicKeyInfo.Read(keyBlob);
                    break;
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    parameters = KeyFormatter.Pkcs1.Read(keyBlob);
                    break;
                default:
                    throw new NotSupportedException();
            }

            // Inject the PKCS#1 public key into the KeyChain.
            string keyIdentifier = Guid.NewGuid().ToString();
            string publicKeyIdentifier = RsaCryptographicKey.GetPublicKeyIdentifierWithTag(keyIdentifier);
            var keyQueryDictionary = RsaCryptographicKey.CreateKeyQueryDictionary(publicKeyIdentifier);
            keyQueryDictionary[KSec.ValueData] = NSData.FromArray(KeyFormatter.Pkcs1.Write(parameters, includePrivateKey: false));
            keyQueryDictionary[KSec.AttrKeyClass] = KSec.AttrKeyClassPublic;
            keyQueryDictionary[KSec.ReturnRef] = NSNumber.FromBoolean(true);
            IntPtr resultHandle;
            int status = RsaCryptographicKey.SecItemAdd(keyQueryDictionary.Handle, out resultHandle);
            if (resultHandle != IntPtr.Zero)
            {
                var key = new SecKey(resultHandle, true);
                return new RsaCryptographicKey(key, keyIdentifier, this.Algorithm);
            }
            else
            {
                throw new InvalidOperationException("SecItemAdd return " + status);
            }
        }

        /// <summary>
        /// Imports an RSA key into the iOS keychain.
        /// </summary>
        /// <param name="parameters">The RSA parameters.</param>
        /// <param name="tag">The tag by which this key will be known.</param>
        /// <returns>The security key.</returns>
        private static SecKey ImportKey(RSAParameters parameters, string tag)
        {
            using (var keyQueryDictionary = RsaCryptographicKey.CreateKeyQueryDictionary(tag))
            {
                byte[] pkcs1Key = KeyFormatter.Pkcs1.Write(parameters, parameters.D != null);
                keyQueryDictionary[KSec.ValueData] = NSData.FromArray(pkcs1Key);
                keyQueryDictionary[KSec.AttrKeyClass] = parameters.D != null ? KSec.AttrKeyClassPrivate : KSec.AttrKeyClassPublic;
                keyQueryDictionary[KSec.ReturnRef] = NSNumber.FromBoolean(true);
                IntPtr handle;
                int status = RsaCryptographicKey.SecItemAdd(keyQueryDictionary.Handle, out handle);
                Verify.Operation(status == 0, "SecItemAdd returned {0}", status);
                return new SecKey(handle, true);
            }
        }
    }
}
