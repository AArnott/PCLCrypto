#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using PCLCrypto;
using PCLCrypto.Tests;
using Xunit;

public class CryptographicEngineAsymmetricTests
{
    private const string AesKeyMaterial = "T1kMUiju2rHiRyhJKfo/Jg==";

    private static readonly ICryptographicKey rsaSha1SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
      .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1)
      .CreateKeyPair(512);

    private static readonly ICryptographicKey rsaSha256SigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
        .OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha256)
        .CreateKeyPair(512);

    private static readonly ICryptographicKey rsaEncryptingKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
        .OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1)
        .CreateKeyPair(512);

    private static readonly ICryptographicKey ecdsaSigningKey;

    private static object[][] signingAndHashParameters;

    /// <summary>
    /// Data the fits within a single cryptographic block.
    /// </summary>
    private readonly byte[] data = new byte[] { 0x3, 0x5, 0x8 };

    static CryptographicEngineAsymmetricTests()
    {
        try
        {
            ecdsaSigningKey = WinRTCrypto.AsymmetricKeyAlgorithmProvider
                .OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256)
                .CreateKeyPair(256);
        }
        catch (NotSupportedException)
        {
            // ECDSA is not supported on this platform.
        }
    }

    public static object[][] SigningParameters
    {
        get
        {
            return SigningAndHashParameters.Select(
                testCase => new object[] { testCase[0] }).ToArray();
        }
    }

    public static object[][] SigningAndHashParameters
    {
        get
        {
            if (signingAndHashParameters == null)
            {
                var result = new List<object[]>
                {
                    new object[] { WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha1).CreateKeyPair(512), HashAlgorithm.Sha1 },
                    new object[] { WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaSignPkcs1Sha256).CreateKeyPair(512), HashAlgorithm.Sha256 },
                };

                try
                {
                    result.Add(new object[] { WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256).CreateKeyPair(256), HashAlgorithm.Sha256 });
                    Debug.WriteLine("ECDSA tests skipped due to no support on the platform.");
                }
                catch (NotSupportedException)
                {
                }

                signingAndHashParameters = result.ToArray();
            }

            return signingAndHashParameters;
        }
    }

    [Fact]
    public void Sign_NullKey()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Sign(null, this.data));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void Sign_NullData(ICryptographicKey key)
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.Sign(key, null));
    }

    [Fact]
    public void VerifySignature_NullKey()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(null, this.data, new byte[2]));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void VerifySignature_NullData(ICryptographicKey key)
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(key, null, new byte[2]));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void VerifySignature_NullSignature(ICryptographicKey key)
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignature(key, this.data, null));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void SignAndVerifySignature(ICryptographicKey key)
    {
        try
        {
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(key, this.data);
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(key, this.data, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(key, PclTestUtilities.Tamper(this.data), signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(key, this.data, PclTestUtilities.Tamper(signature)));
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
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(rsaSha1SigningKey, this.data);
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(rsaSha256SigningKey, this.data, signature));
        }
        catch (NotSupportedException)
        {
            Debug.WriteLine("Not supported by the platform.");
        }
    }

    [Fact]
    public void SignHashedData_NullKey()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.SignHashedData(null, this.data));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void SignHashedData_NullHash(ICryptographicKey key)
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.SignHashedData(key, null));
    }

    [Fact]
    public void VerifySignatureWithHashInput_NullKey()
    {
        var signature = new byte[23];
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(null, this.data, signature));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void VerifySignatureWithHashInput_NullData(ICryptographicKey key)
    {
        var signature = new byte[23];
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, null, signature));
    }

    [Theory, MemberData(nameof(SigningParameters))]
    public void VerifySignatureWithHashInput_NullSignature(ICryptographicKey key)
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, this.data, null));
    }

    [Theory, MemberData(nameof(SigningAndHashParameters))]
    public void SignHashedData_VerifySignatureWithHashInput(ICryptographicKey key, HashAlgorithm hashAlgorithm)
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(hashAlgorithm)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(key, hash);
            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, hash, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, hash, PclTestUtilities.Tamper(signature)));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, PclTestUtilities.Tamper(this.data), signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Theory, MemberData(nameof(SigningAndHashParameters))]
    public void SignHashedData_VerifySignature(ICryptographicKey key, HashAlgorithm hashAlgorithm)
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(hashAlgorithm)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(key, hash);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignature(key, this.data, signature));
        }
        catch (NotSupportedException)
        {
            // Not all platforms support this.
            Debug.WriteLine("Skipped test for unsupported functionality on this platform.");
        }
    }

    [Theory, MemberData(nameof(SigningAndHashParameters))]
    public void Sign_VerifySignatureWithHashInput(ICryptographicKey key, HashAlgorithm hashAlgorithm)
    {
        try
        {
            byte[] hash = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(hashAlgorithm)
                .HashData(this.data);
            byte[] signature = WinRTCrypto.CryptographicEngine.Sign(key, this.data);

            Assert.True(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(key, hash, signature));
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
            byte[] signature = WinRTCrypto.CryptographicEngine.SignHashedData(rsaSha1SigningKey, hash);
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignature(rsaSha256SigningKey, this.data, signature));
            Assert.False(WinRTCrypto.CryptographicEngine.VerifySignatureWithHashInput(rsaSha256SigningKey, hash, signature));
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
            rsaEncryptingKey,
            keyMaterialBytes,
            null);
        CollectionAssertEx.AreNotEqual(keyMaterialBytes, cipherText);
        byte[] plainText = WinRTCrypto.CryptographicEngine.Decrypt(rsaEncryptingKey, cipherText, null);
        CollectionAssertEx.AreEqual(keyMaterialBytes, plainText);
    }
}
#endif
