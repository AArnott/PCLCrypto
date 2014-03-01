namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

    [TestClass]
    public class PclCryptoStreamTests : CryptoStreamTests
    {
        protected override Stream CreateCryptoStream(Stream target, ICryptoTransform transform, CryptoStreamMode mode)
        {
            return new CryptoStream(target, transform, mode);
        }

        protected override void FlushFinalBlock(Stream stream)
        {
            ((CryptoStream)stream).FlushFinalBlock();
        }
    }
}
