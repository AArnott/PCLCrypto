using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class DeriveBytesTests
{
    private const string Password1 = "Password";
    private const string DerivedKey = "S23vp2E3VXpRGQ==";
    private static readonly byte[] Salt2 = new byte[] { 0x1, 0x3, 0x2, 0x5, 0x3, 0x6, 0x7, 0x8 };
    private static readonly byte[] Salt1 = new byte[] { 0x1, 0x2, 0x4, 0x5, 0x3, 0x6, 0x7, 0x8 };

    [Fact]
    public void GetBytes()
    {
        byte[] keyFromPassword = NetFxCrypto.DeriveBytes.GetBytes(Password1, Salt1, 5, 10);
        byte[] keyFromBytes = NetFxCrypto.DeriveBytes.GetBytes(Encoding.UTF8.GetBytes(Password1), Salt1, 5, 10);
        CollectionAssertEx.AreEqual(keyFromPassword, keyFromBytes);
        Assert.Equal(DerivedKey, Convert.ToBase64String(keyFromPassword));

        byte[] keyWithOtherSalt = NetFxCrypto.DeriveBytes.GetBytes(Password1, Salt2, 5, 10);
        CollectionAssertEx.AreNotEqual(keyFromPassword, keyWithOtherSalt);
    }

    [Fact]
    public void GetBytes_NullBytes()
    {
        Assert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes((byte[])null, Salt1, 5, 10));
    }

    [Fact]
    public void GetBytes_NullPassword()
    {
        Assert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes((string)null, Salt1, 5, 10));
    }

    [Fact]
    public void GetBytes_Password_NullSalt()
    {
        Assert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes(Password1, null, 5, 10));
    }

    [Fact]
    public void GetBytes_Bytes_NullSalt()
    {
        Assert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes(Encoding.UTF8.GetBytes(Password1), null, 5, 10));
    }
}
