#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using PCLCrypto;
using PCLCrypto.Tests;
using Xunit;

public class CryptographicEngineAsymmetricTests
{
    private const string AesKeyMaterial = "T1kMUiju2rHiRyhJKfo/Jg==";

    private readonly ICryptographicKey rsaSha1SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
      .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1)
      .CreateKeyPair(512);

    private readonly ICryptographicKey rsaSha256SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
        .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha256)
        .CreateKeyPair(512);

    private readonly ICryptographicKey rsaEncryptingKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
        .OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1)
        .CreateKeyPair(512);

    private readonly ICryptographicKey ecdsaSigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
        .OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256)
        .CreateKeyPair(256);

    /// <summary>
    /// Data the fits within a single cryptographic block.
    /// </summary>
    private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };

    [Fact]
    public void Sign_NullInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Sign(null, this.data));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, null));
    }

    [Fact]
    public void VerifySignature_NullInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(null, this.data, new byte[2]));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, null, new byte[2]));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, null));
    }

    [Fact]
    public void SignAndVerifySignatureRsaSha1()
    {
        byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);
        Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, PclTestUtilities.Tamper(this.data), signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, PclTestUtilities.Tamper(signature)));
    }

    [Fact]
    public void SignAndVerifySignatureECDsa()
    {
        byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.ecdsaSigningKey, this.data);
        Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.ecdsaSigningKey, this.data, signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.ecdsaSigningKey, PclTestUtilities.Tamper(this.data), signature));
        Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.ecdsaSigningKey, this.data, PclTestUtilities.Tamper(signature)));
    }

    [Fact]
    public void SignAndVerifySignatureRsaSha256()
    {
        try
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, PclTestUtilities.Tamper(signature)));
        }
        catch (NotSupportedException)
        {
            Debug.WriteLine("Not supported by the platform.");
        }
    }

    [Fact]
    public void SignAndVerifySignatureRsa_WrongHashAlgorithm()
    {
        try
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
        }
        catch (NotSupportedException)
        {
            Debug.WriteLine("Not supported by the platform.");
        }
    }

    [Fact]
    public void SignHashedData_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.SignHashedData(null, this.data));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, null));
    }

    [Fact]
    public void VerifySignatureWithHashInput_InvalidInputs()
    {
        var signature = new byte[23];
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(null, this.data, signature));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, null, signature));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, this.data, null));
    }

    [Fact]
    public void SignHashedData_VerifySignatureWithHashInput_Sha1()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, PclTestUtilities.Tamper(signature)));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, PclTestUtilities.Tamper(this.data), signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void SignHashedData_VerifySignature_Sha1()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha1SigningKey, this.data, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void Sign_VerifySignatureWithHashInput_Sha1()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha1SigningKey, this.data);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha1SigningKey, hash, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void SignHashedData_VerifySignatureWithHashInput_Sha256()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, PclTestUtilities.Tamper(signature)));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, PclTestUtilities.Tamper(this.data), signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void SignHashedData_VerifySignature_Sha256()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha256SigningKey, hash);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void Sign_VerifySignatureWithHashInput_Sha256()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256)
             .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(this.rsaSha256SigningKey, this.data);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
    public void SignHashedData_VerifySignatureWithHashInput_WrongHashAlgorithm()
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1)
            .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(this.rsaSha1SigningKey, hash);
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(this.rsaSha256SigningKey, this.data, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(this.rsaSha256SigningKey, hash, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Fact]
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
#endif
