// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using PCLCrypto;
using Validation;
using Xunit;
using Xunit.Abstractions;

public class CryptographicEngineTests
{
    private const string AesKeyMaterial = "T1kMUiju2rHiRyhJKfo/Jg==";
    private const string DataAesCiphertextBase64 = "3ChRgsiJ0mXxJIEQS5Z4NA==";

#if SILVERLIGHT
    private const string SkipIfOnlyStandardAESSupported = "Only standard AES is supported.";
#else
    private const string SkipIfOnlyStandardAESSupported = null;
#endif

    /// <summary>
    /// Data the fits within a single cryptographic block.
    /// </summary>
    private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };

    /// <summary>
    /// Data that exceeds the length of a cryptographic block.
    /// </summary>
    private readonly byte[] bigData = new byte[] { 0x3, 0x5, 0x8, 0x11, 0x13, 0x15, 0x17, 0x19, 0x21, 0x23, 0x25, 0x27, 0x29, 0x31, 0x33, 0x35, 0x37, 0x39, 0x41, 0x43, 0x45 };

    private readonly ICryptographicKey macKey = WinRTCrypto.MacAlgorithmProvider
        .OpenAlgorithm(MacAlgorithm.HmacSha1)
        .CreateKey(new byte[] { 0x2, 0x4, 0x6 });

    private readonly ICryptographicKey aesKey = WinRTCrypto.SymmetricKeyAlgorithmProvider
        .OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7)
        .CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));

    private readonly ICryptographicKey aesKeyZerosPadding;

    private readonly ICryptographicKey aesKeyNoPadding = CreateKey(SymmetricAlgorithm.AesCbc, AesKeyMaterial);

    private readonly ITestOutputHelper logger;

    public CryptographicEngineTests(ITestOutputHelper logger)
    {
        this.logger = logger;
        try
        {
            this.aesKeyZerosPadding = WinRTCrypto.SymmetricKeyAlgorithmProvider
                .OpenAlgorithm(SymmetricAlgorithmName.Aes, SymmetricAlgorithmMode.Cbc, SymmetricAlgorithmPadding.Zeros)
                .CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));
        }
        catch (NotSupportedException)
        {
        }
    }

    private static byte[] IV => Convert.FromBase64String("reCDYoG9G+4xr15Am15N+w==");

    [Fact]
    public void SignAndVerifySignatureMac()
    {
        byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.macKey, this.data);
        Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, PclTestUtilities.Tamper(this.data), signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.macKey, this.data, PclTestUtilities.Tamper(signature)));
    }

    [Fact]
    public void Encrypt_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Encrypt(null, this.data, null));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, null, null));
    }

    [Fact]
    public void Decrypt_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Decrypt(null, this.data, null));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, null, null));
    }

    [Fact]
    public void EncryptAndDecrypt_AES_NoIV()
    {
        byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, this.data, null);
        CollectionAssertEx.AreNotEqual(this.data, cipherText);
        Assert.Equal("oCSAA4sUCGa5ukwSJdeKWw==", Convert.ToBase64String(cipherText));
        byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, cipherText, null);
        CollectionAssertEx.AreEqual(this.data, plainText);
    }

    [Fact]
    public void EncryptAndDecrypt_AES_IV()
    {
        byte[] iv = IV;
        byte[] cipherText = WinRTCrypto.CryptographicEngine.Encrypt(this.aesKey, this.data, iv);
        CollectionAssertEx.AreNotEqual(this.data, cipherText);
        Assert.Equal(DataAesCiphertextBase64, Convert.ToBase64String(cipherText));
        Assert.Equal<byte>(iv, IV); // ensure IV wasn't tampered with

        byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, cipherText, iv);
        CollectionAssertEx.AreEqual(this.data, plainText);
        Assert.Equal<byte>(iv, IV); // ensure IV wasn't tampered with
    }

    [Theory]
    [InlineData(0, SymmetricAlgorithmPadding.None, "")]
    [InlineData(0, SymmetricAlgorithmPadding.PKCS7, "+4HMuhSFPVoZ8cmo4//fRw==")]
    [InlineData(0, SymmetricAlgorithmPadding.Zeros, "")]
    [InlineData(4, SymmetricAlgorithmPadding.None, null)]
    [InlineData(4, SymmetricAlgorithmPadding.PKCS7, "nntSI7AkwvmbtLNSJoZlRg==")]
    [InlineData(4, SymmetricAlgorithmPadding.Zeros, "SJZigEu6012wSKJ+u/203Q==")]
    [InlineData(16, SymmetricAlgorithmPadding.None, "Kjgd8dnw3a9ZDcNxEzAj8A==")]
    [InlineData(16, SymmetricAlgorithmPadding.PKCS7, "Kjgd8dnw3a9ZDcNxEzAj8LYap900oNM9hh1Kw06vzl0=")]
    [InlineData(16, SymmetricAlgorithmPadding.Zeros, "Kjgd8dnw3a9ZDcNxEzAj8A==")]
    [InlineData(18, SymmetricAlgorithmPadding.None, null)]
    [InlineData(18, SymmetricAlgorithmPadding.PKCS7, "Kjgd8dnw3a9ZDcNxEzAj8IkJnj6bjxQM7ZJx8Nrxxjc=")]
    [InlineData(18, SymmetricAlgorithmPadding.Zeros, "Kjgd8dnw3a9ZDcNxEzAj8Jg2Z+cLYaP28bM3geHNT3Q=")]
    public void EncryptDecrypt_AES(int inputLength, SymmetricAlgorithmPadding padding, string expectedCiphertext)
    {
        byte[] iv = IV;
        byte[] plaintext = new byte[inputLength];
        Array.Copy(this.bigData, plaintext, inputLength);
        using (var algorithm = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmName.Aes, SymmetricAlgorithmMode.Cbc, padding))
        {
            using (var key = algorithm.CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial)))
            {
                if (expectedCiphertext == null)
                {
                    Assert.Throws<ArgumentException>(
                        () => WinRTCrypto.CryptographicEngine.Encrypt(key, plaintext, iv));
                }
                else
                {
                    byte[] actualCipherText = WinRTCrypto.CryptographicEngine.Encrypt(key, plaintext, iv);
                    Assert.Equal(
                        expectedCiphertext,
                        Convert.ToBase64String(actualCipherText));

                    byte[] expectedPlainText = plaintext;
                    if (!PaddingPreservesPlaintextLength(padding))
                    {
                        // Therefore the expected decrypted value will have a length that is a multiple
                        // of the block length.
                        int blockLength = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmName.Aes, SymmetricAlgorithmMode.Cbc, SymmetricAlgorithmPadding.Zeros)
                            .BlockLength;
                        int bytesBeyondLastBlockLength = expectedPlainText.Length % blockLength;
                        if (bytesBeyondLastBlockLength > 0)
                        {
                            int growBy = blockLength - bytesBeyondLastBlockLength;
                            Array.Resize(ref expectedPlainText, expectedPlainText.Length + growBy);
                        }
                    }

                    byte[] actualPlainText = WinRTCrypto.CryptographicEngine.Decrypt(key, actualCipherText, iv);

                    Assert.Equal(
                        Convert.ToBase64String(expectedPlainText),
                        Convert.ToBase64String(actualPlainText));
                }
            }
        }
    }

    [Fact]
    public void Decrypt_PartialBlockInput()
    {
        byte[] data = new byte[4];
        byte[] iv = IV;
        Assert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKeyNoPadding, data, iv));
        Assert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, data, iv));
    }

    [Fact]
    public void Decrypt_EmptyInput()
    {
        byte[] iv = IV;
        var data = new byte[0];
        Assert.Equal(0, WinRTCrypto.CryptographicEngine.Decrypt(this.aesKeyNoPadding, data, iv).Length);
        Assert.Equal(0, WinRTCrypto.CryptographicEngine.Decrypt(this.aesKey, data, iv).Length);
    }

    [Fact]
    public void CreateEncryptor_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.CreateEncryptor(null, IV));
    }

    [Fact]
    public void CreateDecryptor_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.CreateDecryptor(null, IV));
    }

    [Fact]
    public void CreateEncryptor()
    {
        var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey, IV);
        byte[] cipherText = encryptor.TransformFinalBlock(this.data, 0, this.data.Length);

        Assert.Equal(DataAesCiphertextBase64, Convert.ToBase64String(cipherText));
    }

    [Fact]
    public void StreamingCipherKeyRetainsStateAcrossOperations_Encrypt()
    {
        // NetFX doesn't support RC4. If another streaming cipher is ever added to the suite,
        // this test should be modified to use that cipher to test the NetFx PCL wrapper for
        // streaming cipher behavior.
        var symmetricAlgorithm = SymmetricAlgorithmName.Rc4;
        var mode = SymmetricAlgorithmMode.Streaming;
        var padding = SymmetricAlgorithmPadding.None;
        try
        {
            var algorithmProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(symmetricAlgorithm, mode, padding);
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
            Assert.Equal(
                Convert.ToBase64String(allCiphertext),
                Convert.ToBase64String(incrementalResult));
        }
        catch (NotSupportedException)
        {
            this.logger.WriteLine("{0} not supported by this platform.", symmetricAlgorithm);
        }
    }

    [Fact(Skip = SkipIfOnlyStandardAESSupported)]
    public void KeyStateResetIfAndOnlyIfInitVectorIsSupplied()
    {
        this.KeyStateResetIfAndOnlyIfInitVectorIsSupplied(WinRTCrypto.CryptographicEngine.Encrypt);
        this.KeyStateResetIfAndOnlyIfInitVectorIsSupplied(WinRTCrypto.CryptographicEngine.Decrypt);
    }

    [Fact]
    public void KeyStateResetWithNullIVWhenPaddingIsPresent()
    {
        var algorithm = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        var data = WinRTCrypto.CryptographicBuffer.GenerateRandom((uint)algorithm.BlockLength);
        var key = algorithm.CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));

        // When padding is used, the key always resets state for each operation,
        // even when IV is null.
        byte[] cipherText1 = WinRTCrypto.CryptographicEngine.Encrypt(key, data, null);
        byte[] cipherText2 = WinRTCrypto.CryptographicEngine.Encrypt(key, data, null);

        Assert.Equal<byte>(cipherText1, cipherText2);
    }

    [Fact]
    public void CreateEncryptor_SymmetricEncryptionEquivalence()
    {
        foreach (SymmetricAlgorithm symmetricAlgorithm in Enum.GetValues(typeof(SymmetricAlgorithm)))
        {
            try
            {
                var algorithmProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(symmetricAlgorithm);
                uint keyLength = GetKeyLength(symmetricAlgorithm.GetName(), algorithmProvider);

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
                        Assert.Equal(
                            Convert.ToBase64String(expected),
                            Convert.ToBase64String(actual));
                    }
                }

                this.logger.WriteLine("Algorithm {0} passed.", symmetricAlgorithm);
            }
            catch (NotSupportedException)
            {
                this.logger.WriteLine("Algorithm {0} is not supported on this platform.", symmetricAlgorithm);
            }
        }
    }

    [Fact]
    public void CreateEncryptor_AcceptsNullIV()
    {
        var encryptor = WinRTCrypto.CryptographicEngine.CreateEncryptor(this.aesKey, null);
        Assert.NotNull(encryptor);
    }

    [Fact]
    public void CreateDecryptor_AcceptsNullIV()
    {
        var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey, null);
        Assert.NotNull(decryptor);
    }

    [Fact]
    public void CreateDecryptor()
    {
        byte[] cipherText = Convert.FromBase64String(DataAesCiphertextBase64);
        var decryptor = WinRTCrypto.CryptographicEngine.CreateDecryptor(this.aesKey, IV);
        byte[] plaintext = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
        CollectionAssertEx.AreEqual(this.data, plaintext);
    }

    [Fact]
    public void EncryptDecryptStreamChain()
    {
        byte[] data = this.data;
        this.EncryptDecryptStreamChain(data);
    }

    [Fact]
    public void EncryptDecryptStreamChain_Multiblock()
    {
        this.EncryptDecryptStreamChain(this.bigData);
    }

    private static uint GetKeyLength(SymmetricAlgorithmName symmetricAlgorithm, ISymmetricKeyAlgorithmProvider algorithmProvider)
    {
        uint keyLength;
        switch (symmetricAlgorithm)
        {
            case SymmetricAlgorithmName.TripleDes:
                keyLength = (uint)algorithmProvider.BlockLength * 3;
                break;
            default:
                keyLength = (uint)algorithmProvider.BlockLength;
                break;
        }

        return keyLength;
    }

    private static bool PaddingPreservesPlaintextLength(SymmetricAlgorithmPadding padding)
    {
        return padding != SymmetricAlgorithmPadding.Zeros;
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

    private void KeyStateResetIfAndOnlyIfInitVectorIsSupplied(Func<ICryptographicKey, byte[], byte[], byte[]> cipherFunc)
    {
        var algorithm = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbc);
        var data1 = WinRTCrypto.CryptographicBuffer.GenerateRandom((uint)algorithm.BlockLength);
        var data2 = WinRTCrypto.CryptographicBuffer.GenerateRandom((uint)algorithm.BlockLength);
        var data1and2 = new byte[data1.Length + data2.Length];
        Array.Copy(data1, data1and2, data1.Length);
        Array.Copy(data2, 0, data1and2, data1.Length, data2.Length);

        var key = algorithm.CreateSymmetricKey(Convert.FromBase64String(AesKeyMaterial));

        // Encrypt the two blocks in separate operations, passing null for the IV the second time.
        byte[] cipherText1 = cipherFunc(key, data1, this.iv);
        byte[] cipherText2 = cipherFunc(key, data2, null);
        byte[] cipherText1and2Stitched = new byte[cipherText1.Length + cipherText2.Length];
        Array.Copy(cipherText1, cipherText1and2Stitched, cipherText1.Length);
        Array.Copy(cipherText2, 0, cipherText1and2Stitched, cipherText1.Length, cipherText2.Length);

        // Encrypt the two blocks at once, specifying the IV, which should have reset the state of the key.
        byte[] cipherText1and2 = cipherFunc(key, data1and2, this.iv);

        // Assert that both approaches produce the same result.
        Assert.Equal<byte>(cipherText1and2, cipherText1and2Stitched);
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
