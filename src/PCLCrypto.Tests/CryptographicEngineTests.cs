namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

    [TestClass]
    public class CryptographicEngineTests
    {
        private const string AesKeyMaterial = "T1kMUiju2rHiRyhJKfo/Jg==";

        private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };
        private readonly ICryptographicKey rsaSigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1)
            .CreateKeyPair(512);

        private readonly ICryptographicKey rsaEncryptingKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1)
            .CreateKeyPair(512);

        private readonly ICryptographicKey macKey = WinRTCrypto.MacAlgorithmProvider
            .OpenAlgorithm(MacAlgorithm.HmacSha1)
            .CreateKey(new byte[] { 0x2, 0x4, 0x6 });

        private readonly ICryptographicKey aesKey = WinRTCrypto.SymmetricKeyAlgorithmProvider
            .OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
            .CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));

        private readonly byte[] iv = Convert.FromBase64String("reCDYoG9G+4xr15Am15N+w==");

        [TestMethod]
        public void Sign_NullInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Sign(null, this.data));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Sign(this.rsaSigningKey, null));
        }

        [TestMethod]
        public void VerifySignature_NullInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(null, this.data, new byte[2]));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSigningKey, null, new byte[2]));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSigningKey, this.data, null));
        }

        [TestMethod]
        public void SignAndVerifySignatureRsa()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSigningKey, this.data);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSigningKey, this.data, signature));
        }

        [TestMethod]
        public void SignatureAndVerifyTamperedSignatureRsa()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSigningKey, this.data);

            // Tamper with the signature.
            signature[signature.Length - 1] += 1;
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSigningKey, this.data, signature));
        }

        [TestMethod]
        public void SignatureAndVerifyTamperedDataRsa()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSigningKey, this.data);

            // Tamper with the data.
            byte[] tamperedData = new byte[this.data.Length];
            Array.Copy(this.data, tamperedData, this.data.Length);
            tamperedData[tamperedData.Length - 1] += 1;
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSigningKey, tamperedData, signature));
        }

        [TestMethod]
        public void SignAndVerifySignatureMac()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.macKey, this.data);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, signature));
        }

        [TestMethod]
        public void SignatureAndVerifyTamperedSignatureMac()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.macKey, this.data);

            // Tamper with the signature.
            signature[signature.Length - 1] += 1;
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, signature));
        }

        [TestMethod]
        public void SignatureAndVerifyTamperedDataMac()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.macKey, this.data);

            // Tamper with the data.
            byte[] tamperedData = new byte[this.data.Length];
            Array.Copy(this.data, tamperedData, this.data.Length);
            tamperedData[tamperedData.Length - 1] += 1;
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, tamperedData, signature));
        }

        [TestMethod]
        public void Encrypt_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Encrypt(null, this.data, null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, null, null));
        }

        [TestMethod]
        public void Decrypt_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Decrypt(null, this.data, null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, null, null));
        }

        [TestMethod]
        public void EncryptAndDecrypt_AES_NoIV()
        {
            byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, this.data, null);
            CollectionAssertEx.AreNotEqual(this.data, cipherText);
            Assert.AreEqual("oCSAA4sUCGa5ukwSJdeKWw==", Convert.ToBase64String(cipherText));
            byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, cipherText, null);
            CollectionAssertEx.AreEqual(this.data, plainText);
        }

        [TestMethod]
        public void EncryptAndDecrypt_AES_IV()
        {
            byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, this.data, this.iv);
            CollectionAssertEx.AreNotEqual(this.data, cipherText);
            Assert.AreEqual("3ChRgsiJ0mXxJIEQS5Z4NA==", Convert.ToBase64String(cipherText));
            byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, cipherText, this.iv);
            CollectionAssertEx.AreEqual(this.data, plainText);
        }

        [TestMethod]
        public void EncryptAndDecrypt_RSA()
        {
            byte[] keyMaterialBytes = Convert.FromBase64String(AesKeyMaterial);
            byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(
                this.rsaEncryptingKey, 
                keyMaterialBytes,
                null);
            CollectionAssertEx.AreNotEqual(keyMaterialBytes, cipherText);
            byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(this.rsaEncryptingKey, cipherText, null);
            CollectionAssertEx.AreEqual(keyMaterialBytes, plainText);
        }
    }
}
