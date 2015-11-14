using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class SymmetricKeyAlgorithmProviderTests
{
    private readonly byte[] keyMaterial = new byte[16] { 0x2, 0x5, 0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, };

    [Fact]
    public void BlockLength()
    {
        ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        Assert.NotNull(provider);
        Assert.Equal(16, provider.BlockLength);
    }

    [Fact]
    public void CreateSymmetricKey_InvalidInputs()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        Assert.Throws<ArgumentNullException>(
            () => provider.CreateSymmetricKey(null));
        Assert.Throws<ArgumentException>(
            () => provider.CreateSymmetricKey(new byte[0]));
        Assert.Throws<ArgumentException>(
            () =>
            {
                var key = provider.CreateSymmetricKey(new byte[4]);
                WinRTCrypto.CryptographicEngine.Encrypt(key, new byte[] { 1, 2, 3 });
            });
    }

    [Fact]
    public void CreateSymmetricKey_AesCbcPkcs7()
    {
        this.CreateSymmetricKeyHelper(SymmetricAlgorithm.AesCbcPkcs7);
    }

#if !(SILVERLIGHT || __IOS__)
    [Fact]
    public void CreateSymmetricKey_AesEcbPkcs7()
    {
        this.CreateSymmetricKeyHelper(SymmetricAlgorithm.AesEcbPkcs7);
    }
#endif

    [Fact]
    public void CreateSymmetricKey_Export()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.Throws<NotSupportedException>(
            () => key.Export());
    }

    [Fact]
    public void CreateSymmetricKey_ExportPublicKey()
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.Throws<NotSupportedException>(
            () => key.ExportPublicKey());
    }

    private void CreateSymmetricKeyHelper(SymmetricAlgorithm algorithm)
    {
        var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm);
        ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
        Assert.NotNull(key);
        Assert.Equal(this.keyMaterial.Length * 8, key.KeySize);
    }
}
