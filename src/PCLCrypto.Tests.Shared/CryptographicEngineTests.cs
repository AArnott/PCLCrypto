namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
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

        /// <summary>
        /// Data the fits within a single cryptographic block.
        /// </summary>
        private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };

        /// <summary>
        /// Data that exceeds the length of a cryptographic block.
        /// </summary>
        private readonly byte[] bigData = new byte[] { 0x3, 0x5, 0x8, 0x11, 0x13, 0x15, 0x17, 0x19, 0x21, 0x23, 0x25, 0x27, 0x29, 0x31, 0x33, 0x35, 0x37, 0x39, 0x41, 0x43, 0x45 };

#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto
        private readonly ICryptographicKey rsaSha1SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1)
            .CreateKeyPair(512);

        private readonly ICryptographicKey rsaSha256SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha256)
            .CreateKeyPair(512);

        private readonly ICryptographicKey rsaEncryptingKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
            .OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1)
            .CreateKeyPair(512);
#endif

        private readonly ICryptographicKey macKey = WinRTCrypto.MacAlgorithmProvider
            .OpenAlgorithm(MacAlgorithm.HmacSha1)
            .CreateKey(new byte[] { 0x2, 0x4, 0x6 });

        private readonly ICryptographicKey aesKey = WinRTCrypto.SymmetricKeyAlgorithmProvider
            .OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
            .CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));

        private readonly ICryptographicKey aesKeyNoPadding = CreateKey(SymmetricAlgorithm.AesCbc, AesKeyMaterial);

        private readonly byte[] iv = Convert.FromBase64String("reCDYoG9G+4xr15Am15N+w==");

#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto

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
            try
            {
                byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);
                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, PclTestUtilities.Tamper(signature)));
            }
            catch (NotSupportedException)
            {
                Debug.WriteLine("Not supported by the platform.");
            }
        }

        [TestMethod]
        public void SignAndVerifySignatureRsa_WrongHashAlgorithm()
        {
            try
            {
                byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            }
            catch (NotSupportedException)
            {
                Debug.WriteLine("Not supported by the platform.");
            }
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
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                    .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, PclTestUtilities.Tamper(signature)));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, PclTestUtilities.Tamper(this.data), signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void SignHashedData_VerifySignature_Sha1()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                    .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);

                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void Sign_VerifySignatureWithHashInput_Sha1()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                    .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);

                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void SignHashedData_VerifySignatureWithHashInput_Sha256()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                    .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);
                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, PclTestUtilities.Tamper(signature)));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void SignHashedData_VerifySignature_Sha256()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                    .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);

                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void Sign_VerifySignatureWithHashInput_Sha256()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                 .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);

                Assert.IsTrue(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

        [TestMethod]
        public void SignHashedData_VerifySignatureWithHashInput_WrongHashAlgorithm()
        {
            try
            {
                byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
                byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
                Assert.IsFalse(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
            }
            catch (NotSupportedException)
            {
                // Not all platforms support this.
                Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
            }
        }

#endif

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
        public void Encrypt_PartialBlockInput()
        {
            if (this.aesKeyNoPadding != null)
            {
                ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Encrypt(this.aesKeyNoPadding, new byte[4], this.iv));
            }

            byte[] ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, new byte[4], this.iv);
            Assert.AreEqual(16, ciphertext.Length); // 16 is the block size for AES
        }

        [TestMethod]
        public void Decrypt_PartialBlockInput()
        {
            if (this.aesKeyNoPadding != null)
            {
                ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKeyNoPadding, new byte[4], this.iv));
            }

            ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, new byte[4], this.iv));
        }

        [TestMethod]
        public void Encrypt_EmptyInput()
        {
            if (this.aesKeyNoPadding != null)
            {
                ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Encrypt(this.aesKeyNoPadding, new byte[0], this.iv));
            }

            byte[] ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, new byte[0], this.iv);
            Assert.AreEqual(16, ciphertext.Length); // 16 is the block size for AES
        }

        [TestMethod]
        public void Decrypt_EmptyInput()
        {
            if (this.aesKeyNoPadding != null)
            {
                ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKeyNoPadding, new byte[0], this.iv));
            }

            ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, new byte[0], this.iv));
        }

#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto

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

#endif

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
        public void StreamingCipherKeyRetainsStateAcrossOperations_Encrypt()
        {
            // NetFX doesn't support RC4. If another streaming cipher is ever added to the suite,
            // this test should be modified to use that cipher to test the NetFx PCL wrapper for
            // streaming cipher behavior.
            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Rc4;
            try
            {
                var algorithmProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(symmetricAlgorithm);
                uint keyLength = GetKeyLength(symmetricAlgorithm, algorithmProvider);
                byte[] keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength);
                var key1 = algorithmProvider.CreateSymmetricKey(keyMaterial);
                var key2 = algorithmProvider.CreateSymmetricKey(keyMaterial);

                byte[] allData = new byte[] { 1, 2, 3 };
                byte[] allCiphertext = WinRTCrypto.CryptographicEngine.Encrypt(key1, allData);

                var cipherStream = new MemoryStream();
                for (int i = 0; i < allData.Length; i++)
                {
                    byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(key2, new byte[] { allData[i] });
                    cipherStream.Write(cipherText, 0, cipherText.Length);
                }

                byte[] incrementalResult = cipherStream.ToArray();
                Assert.AreEqual(
                    Convert.ToBase64String(allCiphertext),
                    Convert.ToBase64String(incrementalResult));
            }
            catch (NotSupportedException)
            {
                Debug.WriteLine("{0} not supported by this platform.", symmetricAlgorithm);
            }
        }

        [TestMethod]
        public void StreamingCipherKeyRetainsStateAcrossOperations_Decrypt()
        {
            // NetFX doesn't support RC4. If another streaming cipher is ever added to the suite,
            // this test should be modified to use that cipher to test the NetFx PCL wrapper for
            // streaming cipher behavior.
            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.Rc4;
            try
            {
                var algorithmProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(symmetricAlgorithm);
                uint keyLength = GetKeyLength(symmetricAlgorithm, algorithmProvider);
                byte[] keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength);
                var key1 = algorithmProvider.CreateSymmetricKey(keyMaterial);
                var key2 = algorithmProvider.CreateSymmetricKey(keyMaterial);

                byte[] allData = new byte[] { 1, 2, 3 };
                byte[] allCiphertext = WinRTCrypto.CryptographicEngine.Decrypt(key1, allData);

                var cipherStream = new MemoryStream();
                for (int i = 0; i < allData.Length; i++)
                {
                    byte[] cipherText = WinRTCrypto.CryptographicEngine.Decrypt(key2, new byte[] { allData[i] });
                    cipherStream.Write(cipherText, 0, cipherText.Length);
                }

                byte[] incrementalResult = cipherStream.ToArray();
                Assert.AreEqual(
                    Convert.ToBase64String(allCiphertext),
                    Convert.ToBase64String(incrementalResult));
            }
            catch (NotSupportedException)
            {
                Debug.WriteLine("{0} not supported by this platform.", symmetricAlgorithm);
            }
        }

        [TestMethod]
        public void CreateEncryptor_SymmetricEncryptionEquivalence()
        {
            foreach (SymmetricAlgorithm symmetricAlgorithm in Enum.GetValues(typeof(SymmetricAlgorithm)))
            {
                try
                {
                    var algorithmProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(symmetricAlgorithm);
                    uint keyLength = GetKeyLength(symmetricAlgorithm, algorithmProvider);

                    byte[] keyMaterial = WinRTCrypto.CryptographicBuffer.GenerateRandom(keyLength);
                    var key1 = algorithmProvider.CreateSymmetricKey(keyMaterial);
                    var key2 = algorithmProvider.CreateSymmetricKey(keyMaterial); // create a second key so that streaming ciphers will be produce the same result when executed the second time
                    var iv = symmetricAlgorithm.UsesIV() ? WinRTCrypto.CryptographicBuffer.GenerateRandom((uint)algorithmProvider.BlockLength) : null;

                    for (int dataLengthFactor = 1; dataLengthFactor <= 3; dataLengthFactor++)
                    {
                        var data = WinRTCrypto.CryptographicBuffer.GenerateRandom((uint)(dataLengthFactor * algorithmProvider.BlockLength));
                        var expected = WinRTCrypto.CryptographicEngine.Encrypt(key1, data, iv);

                        var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(key2, iv);
                        var actualStream = new MemoryStream();
                        using (var cryptoStream = CryptoStream.WriteTo(actualStream, encryptor))
                        {
                            cryptoStream.Write(data, 0, data.Length);
                            cryptoStream.FlushFinalBlock();

                            byte[] actual = actualStream.ToArray();
                            Assert.AreEqual(
                                Convert.ToBase64String(expected),
                                Convert.ToBase64String(actual));
                        }
                    }

                    Debug.WriteLine("Algorithm {0} passed.", symmetricAlgorithm);
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Algorithm {0} is not supported on this platform.", symmetricAlgorithm);
                }
            }
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
            byte[] data = this.data;
            this.EncryptDecryptStreamChain(data);
        }

        [TestMethod]
        public void EncryptDecryptStreamChain_Multiblock()
        {
            this.EncryptDecryptStreamChain(this.bigData);
        }

        private static uint GetKeyLength(SymmetricAlgorithm symmetricAlgorithm, ISymmetricKeyAlgorithmProvider algorithmProvider)
        {
            uint keyLength;
            switch (symmetricAlgorithm)
            {
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    keyLength = (uint)algorithmProvider.BlockLength * 3;
                    break;
                default:
                    keyLength = (uint)algorithmProvider.BlockLength;
                    break;
            }

            return keyLength;
        }

        private static ICryptographicKey CreateKey(SymmetricAlgorithm algorithm, string keyMaterialBase64)
        {
            try
            {
                return WinRTCrypto.SymmetricKeyAlgorithmProvider
                    .OpenAlgorithm(algorithm)
                    .CreateSymmetricKey(Convert.FromBase64String(keyMaterialBase64));
            }
            catch (NotSupportedException)
            {
                return null;
            }
        }

        private void EncryptDecryptStreamChain(byte[] data)
        {
            var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey);
            var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey);

            var decryptedStream = new MemoryStream();
            using (var decryptingStream = new CryptoStream(decryptedStream, decryptor, CryptoStreamMode.Write))
            {
                using (var encryptingStream = new CryptoStream(decryptingStream, encryptor, CryptoStreamMode.Write))
                {
                    encryptingStream.Write(data, 0, data.Length);
                }
            }

            CollectionAssertEx.AreEqual(data, decryptedStream.ToArray());
        }
    }
}
