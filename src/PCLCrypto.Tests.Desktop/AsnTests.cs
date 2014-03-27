namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLCrypto.Formatters;
    using PCLTesting;

    [TestClass]
    public class AsnTests
    {
        [TestMethod]
        public void ContentsOfVaryingLengths()
        {
            int[] interestingLengths = new int[] { 0, 1, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x100, 0x101, 0x2000 };
            foreach (int length in interestingLengths)
            {
                Console.WriteLine("Testing length {0}", length);
                byte[] encoded = Asn.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Application, Asn.BerPC.Constructed, Asn.BerTag.BitString, new byte[length]));
                var element = Asn.ReadAsn1Elements(encoded).Single();
                Assert.AreEqual(length, element.Content.Length);
            }
        }
    }
}
