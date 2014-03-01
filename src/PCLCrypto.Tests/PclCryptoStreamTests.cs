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
#pragma warning disable 0436
    public class PclCryptoStreamTests : CryptoStreamTests
#pragma warning restore 0436
    {
        [TestMethod]
        public void Ctor_InvalidArgs()
        {
            // NetFx version throws NullReferenceException.
            ExceptionAssert.Throws<ArgumentNullException>(
                () => this.CreateCryptoStream(null, new MockCryptoTransform(5), CryptoStreamMode.Write));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => this.CreateCryptoStream(Stream.Null, null, CryptoStreamMode.Write));
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
}
