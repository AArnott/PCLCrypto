// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PCLCrypto;

public static class PclTestUtilities
{
    public static string Hex(byte[]? buffer) => buffer != null ? WinRTCrypto.CryptographicBuffer.EncodeToHexString(buffer) : "<null>";

    public static byte[] Tamper(byte[] buffer)
    {
        int index = new Random().Next(buffer.Length);
        var tampered = new byte[buffer.Length];
        Array.Copy(buffer, tampered, buffer.Length);
        tampered[index] = (byte)unchecked(tampered[index] + 1);
        return tampered;
    }

    public static byte[] ToArray(this MemoryStream stream)
    {
        byte[] buffer = new byte[stream.Length];
        long oldPosition = stream.Position;
        stream.Position = 0;
        stream.Read(buffer, 0, buffer.Length);
        stream.Position = oldPosition;
        return buffer;
    }

    public static string GetString(this Encoding encoding, byte[] buffer)
    {
        return encoding.GetString(buffer, 0, buffer.Length);
    }
}
