namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

    [TestClass]
    public class CryptographicEngineTests
    {
        private const string AesKeyMaterial = "T1kMUiju2rHiRyhJKfo/Jg==";
        private const string DataAesCiphertextBase64 = "3ChRgsiJ0mXxJIEQS5Z4NA==";
        private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };
        private readonly ICryptographicKey rsaSha1SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1)
            .CreateKeyPair(512);

        private readonly ICryptographicKey rsaSha256SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha256)
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
                () => WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, null));
        }

        [TestMethod]
        public void VerifySignature_NullInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(null, this.data, new byte[2]));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, null, new byte[2]));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, null));
        }

        [TestMethod]
        public void SignAndVerifySignatureRsaSha1()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, PclTestUtilities.Tamper(this.data), signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, PclTestUtilities.Tamper(signature)));
        }

        [TestMethod]
        public void SignAndVerifySignatureRsaSha256()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, PclTestUtilities.Tamper(signature)));
        }

        [TestMethod]
        public void SignAndVerifySignatureRsa_WrongHashAlgorithm()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
        }

        [TestMethod]
        public void SignHashedData_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.SignHashedData(null, this.data));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, null));
        }

        [TestMethod]
        public void VerifySignatureWithHashInput_InvalidInputs()
        {
            var signature = new byte[23];
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(null, this.data, signature));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, null, signature));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, this.data, null));
        }

        [TestMethod]
        public void SignHashedData_VerifySignatureWithHashInput_Sha1()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, PclTestUtilities.Tamper(signature)));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, PclTestUtilities.Tamper(this.data), signature));
        }

        [TestMethod]
        public void SignHashedData_VerifySignature_Sha1()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);

            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, signature));
        }

        [TestMethod]
        public void Sign_VerifySignatureWithHashInput_Sha1()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);

            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
        }

        [TestMethod]
        public void SignHashedData_VerifySignatureWithHashInput_Sha256()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, PclTestUtilities.Tamper(signature)));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
        }

        [TestMethod]
        public void SignHashedData_VerifySignature_Sha256()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);

            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
        }

        [TestMethod]
        public void Sign_VerifySignatureWithHashInput_Sha256()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);

            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
        }

        [TestMethod]
        public void SignHashedData_VerifySignatureWithHashInput_WrongHashAlgorithm()
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
        }

        [TestMethod]
        public void SignAndVerifySignatureMac()
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.macKey, this.data);
            Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, PclTestUtilities.Tamper(this.data), signature));
            Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, PclTestUtilities.Tamper(signature)));
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
            Assert.AreEqual(DataAesCiphertextBase64, Convert.ToBase64String(cipherText));
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

        [TestMethod]
        public void CreateEncryptor_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.CreateEncryptor(null, this.iv));
        }

        [TestMethod]
        public void CreateDecryptor_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicEngine.CreateDecryptor(null, this.iv));
        }

        [TestMethod]
        public void CreateEncryptor()
        {
            var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey, this.iv);
            byte[] cipherText = encryptor.TransformFinalBlock(this.data, 0, this.data.Length);

            Assert.AreEqual(DataAesCiphertextBase64, Convert.ToBase64String(cipherText));
        }

        [TestMethod]
        public void CreateEncryptor_AcceptsNullIV()
        {
            var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey, null);
            Assert.IsNotNull(encryptor);
        }

        [TestMethod]
        public void CreateDecryptor_AcceptsNullIV()
        {
            var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey, null);
            Assert.IsNotNull(decryptor);
        }

        [TestMethod]
        public void CreateDecryptor()
        {
            byte[] cipherText = Convert.FromBase64String(DataAesCiphertextBase64);
            var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey, this.iv);
            byte[] plaintext = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            CollectionAssertEx.AreEqual(this.data, plaintext);
        }

        [TestMethod]
        public void EncryptDecryptStreamChain()
        {
            var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey);
            var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey);

            var decryptedStream = new MemoryStream();
            using (var decryptingStream = new CryptoStream(decryptedStream, decryptor, CryptoStreamMode.Write))
            {
                using (var encryptingStream = new CryptoStream(decryptingStream, encryptor, CryptoStreamMode.Write))
                {
                    encryptingStream.Write(this.data, 0, this.data.Length);
                }
            }

            CollectionAssertEx.AreEqual(this.data, decryptedStream.ToArray());
        }
    }
}
