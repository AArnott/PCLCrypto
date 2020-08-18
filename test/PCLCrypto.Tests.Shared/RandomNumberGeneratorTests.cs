// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCLCrypto;
using Xunit;

public class RandomNumberGeneratorTests
{
    [Fact]
    public void GetBytes_Null()
    {
        Assert.Throws<ArgumentNullException>(
            () => NetFxCrypto.RandomNumberGenerator.GetBytes(null!));
    }

    [Fact]
    public void GetBytes_Empty()
    {
        var buffer = Array.Empty<byte>();
        NetFxCrypto.RandomNumberGenerator.GetBytes(buffer);
    }

    [Fact]
    public void GetBytes()
    {
        var buffer1 = new byte[4];
        NetFxCrypto.RandomNumberGenerator.GetBytes(buffer1);

        var buffer2 = new byte[4];
        NetFxCrypto.RandomNumberGenerator.GetBytes(buffer2);

        // Verify that the two randomly filled buffers are not equal.
        Assert.True(BitConverter.ToInt32(buffer1, 0) != BitConverter.ToInt32(buffer2, 0));
    }

#if !WINDOWS_UWP
    [Fact]
    public void DesktopBaseClass()
    {
        Assert.True(NetFxCrypto.RandomNumberGenerator is System.Security.Cryptography.RandomNumberGenerator);
    }
#endif

    [Fact]
    public void GetNonZeroBytes()
    {
        var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
        Assert.NotNull(rng);
        byte[] buffer = new byte[15];
        rng!.GetNonZeroBytes(buffer);
        Assert.True(buffer.All(b => b != 0));
    }

    [Fact]
    public void GetNonZeroBytes_Null()
    {
        var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
        Assert.NotNull(rng);
        Assert.Throws<ArgumentNullException>(() => rng!.GetNonZeroBytes(null!));
    }
}
