// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft;
using Xunit;

/// <summary>
/// Ensures that our CryptoStream tests pass on the official
/// .NET Framework's version of CryptoStream as well.
/// </summary>
#pragma warning disable 0436
public class DesktopCryptoStreamTests : CryptoStreamTests
#pragma warning restore 0436
{
    protected override Stream CreateCryptoStream(Stream target, PCLCrypto.ICryptoTransform transform, PCLCrypto.CryptoStreamMode mode, bool leaveOpen = false)
    {
        return new CryptoStream(target, CryptoTransformAdapter.Adapt(transform), ModeAdapter(mode), leaveOpen);
    }

    protected override void FlushFinalBlock(Stream stream)
    {
        ((CryptoStream)stream).FlushFinalBlock();
    }

    private static CryptoStreamMode ModeAdapter(PCLCrypto.CryptoStreamMode mode)
    {
        switch (mode)
        {
            case PCLCrypto.CryptoStreamMode.Read:
                return CryptoStreamMode.Read;
            case PCLCrypto.CryptoStreamMode.Write:
                return CryptoStreamMode.Write;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    private class CryptoTransformAdapter : ICryptoTransform
    {
        private readonly PCLCrypto.ICryptoTransform transform;

        private CryptoTransformAdapter(PCLCrypto.ICryptoTransform transform)
        {
            this.transform = transform;
        }

        public bool CanReuseTransform
        {
            get { return this.transform.CanReuseTransform; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return this.transform.CanTransformMultipleBlocks; }
        }

        public int InputBlockSize
        {
            get { return this.transform.InputBlockSize; }
        }

        public int OutputBlockSize
        {
            get { return this.transform.OutputBlockSize; }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return this.transform.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return this.transform.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        public void Dispose()
        {
            this.transform.Dispose();
        }

        internal static ICryptoTransform? Adapt(PCLCrypto.ICryptoTransform? transform)
        {
            return transform != null ? new CryptoTransformAdapter(transform) : null;
        }
    }
}
