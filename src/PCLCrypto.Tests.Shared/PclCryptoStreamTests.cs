using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

#pragma warning disable 0436
public class PclCryptoStreamTests : CryptoStreamTests
#pragma warning restore 0436
{
    [Fact]
    public void Ctor_InvalidArgs()
    {
        // NetFx version throws NullReferenceException.
        Assert.Throws<ArgumentNullException>(
            () => this.CreateCryptoStream(null, new MockCryptoTransform(5), CryptoStreamMode.Write));
        Assert.Throws<ArgumentNullException>(
            () => this.CreateCryptoStream(Stream.Null, null, CryptoStreamMode.Write));
    }

    [Fact]
    public void Write_NullBuffer()
    {
        using (var stream = this.CreateCryptoStream(Stream.Null, new MockCryptoTransform(5), CryptoStreamMode.Write))
        {
            Assert.Throws<ArgumentNullException>(() => stream.Write(null, 0, 0));
        }
    }

    [Fact]
    public void Read_NullBuffer()
    {
        using (var stream = this.CreateCryptoStream(new MemoryStream(), new MockCryptoTransform(5), CryptoStreamMode.Read))
        {
            Assert.Throws<ArgumentNullException>(() => stream.Read(null, 0, 0));
        }
    }

    [Fact]
    public void WriteTo_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => CryptoStream.WriteTo(null, new MockCryptoTransform(5)));
        Assert.Throws<ArgumentException>(
            () => CryptoStream.WriteTo(Stream.Null));
        Assert.Throws<ArgumentNullException>(
            () => CryptoStream.WriteTo(Stream.Null, null));
    }

    [Fact]
    public void ReadFrom_InvalidInputs()
    {
        Assert.Throws<ArgumentNullException>(
            () => CryptoStream.ReadFrom(null, new MockCryptoTransform(5)));
        Assert.Throws<ArgumentException>(
            () => CryptoStream.ReadFrom(Stream.Null));
        Assert.Throws<ArgumentNullException>(
            () => CryptoStream.ReadFrom(Stream.Null, null));
    }

    [Fact]
    public void WriteTo()
    {
        var t1 = new MockCryptoTransform(6);
        var t2 = new MockCryptoTransform(9);
        var ms = new MemoryStream();
        using (var cryptoStream = CryptoStream.WriteTo(ms, t1, t2))
        {
            cryptoStream.Write(Encoding.UTF8.GetBytes("abcdefghijkl"), 0, 12);
        }

        Assert.Equal("--abcdef-g_hijkl_ZZ", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void ReadFrom()
    {
        var t1 = new MockCryptoTransform(6);
        var t2 = new MockCryptoTransform(9);
        var ms = new MemoryStream(Encoding.UTF8.GetBytes("abcdefghijkl"));
        using (var cryptoStream = CryptoStream.ReadFrom(ms, t1, t2))
        {
            var buffer = new byte[100];
            int bytesRead = cryptoStream.Read(buffer, 0, 100);
            Assert.Equal("--abcdef-g_hijkl_ZZ", Encoding.UTF8.GetString(buffer, 0, bytesRead));
        }
    }

    protected override Stream CreateCryptoStream(Stream target, ICryptoTransform transform, CryptoStreamMode mode)
    {
        return new CryptoStream(target, transform, mode);
    }

    protected override void FlushFinalBlock(Stream stream)
    {
        ((CryptoStream)stream).FlushFinalBlock();
    }
}
