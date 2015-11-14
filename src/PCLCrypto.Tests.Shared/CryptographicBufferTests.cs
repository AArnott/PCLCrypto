using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class CryptographicBufferTests
{
    [Fact]
    public void Compare_NullInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicBuffer.Compare(null, null));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicBuffer.Compare(new byte[0], null));
        Assert.Throws<ArgumentNullException>(
            () => WinRTCrypto.CryptographicBuffer.Compare(null, new byte[0]));
    }

    [Fact]
    public void Compare_EqualBufferLengths()
    {
        Assert.True(WinRTCrypto.CryptographicBuffer.Compare(new byte[2], new byte[2]));
        Assert.True(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1, 0x2 }));
        Assert.False(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x3 }, new byte[] { 0x1, 0x2 }));
        Assert.False(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x3, 0x2 }, new byte[] { 0x1, 0x2 }));
    }

    [Fact]
    public void Compare_UnequalBufferLengths()
    {
        Assert.False(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1 }, new byte[] { 0x1, 0x2 }));
        Assert.False(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1 }));
    }

    [Fact]
    public void GenerateRandom_ZeroLength()
    {
        byte[] buffer = WinRTCrypto.CryptographicBuffer.GenerateRandom(0);
        Assert.Equal(0, buffer.Length);
    }

    [Fact]
    public void EncodeToHexString_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(() => WinRTCrypto.CryptographicBuffer.EncodeToHexString(null));
    }

    [Fact]
    public void EncodeToHexString_EmptyBuffer()
    {
        Assert.Equal(string.Empty, WinRTCrypto.CryptographicBuffer.EncodeToHexString(new byte[0]));
    }

    [Fact]
    public void EncodeToHexString()
    {
        Assert.Equal("00010faefff0", WinRTCrypto.CryptographicBuffer.EncodeToHexString(new byte[] { 0x00, 0x1, 0xf, 0xae, 0xff, 0xf0 }));
    }

    [Fact]
    public void DecodeFromHexString_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(() => WinRTCrypto.CryptographicBuffer.DecodeFromHexString(null));
        Assert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicBuffer.DecodeFromHexString("123")); // odd length
    }

    [Fact]
    public void DecodeFromHexString_EmptyString()
    {
        CollectionAssertEx.AreEqual(new byte[0], WinRTCrypto.CryptographicBuffer.DecodeFromHexString(string.Empty));
    }

    [Fact]
    public void DecodeFromHexString()
    {
        CollectionAssertEx.AreEqual(new byte[] { 0x00, 0x1, 0xf, 0xae, 0xff, 0xf0 }, WinRTCrypto.CryptographicBuffer.DecodeFromHexString("00010faefff0"));
    }

    [Fact]
    public void GenerateRandom()
    {
        byte[] buffer1 = WinRTCrypto.CryptographicBuffer.GenerateRandom(15);
        Assert.Equal(15, buffer1.Length);

        byte[] buffer2 = WinRTCrypto.CryptographicBuffer.GenerateRandom(15);
        Assert.Equal(15, buffer2.Length);

        CollectionAssertEx.AreNotEqual(buffer1, buffer2);
    }

    [Fact]
    public void GenerateRandomNumber()
    {
        uint random1 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();
        uint random2 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();
        uint random3 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();

        // The odds of all three being equal should be *very* small.
        Assert.True(random1 != random2 || random2 != random3);
    }
}
