namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using PCLTesting;

    public static class CollectionAssertEx
    {
        public static void AreEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
        {
            Assert.IsFalse(expected == null ^ actual == null);
            if (expected == null)
            {
                return;
            }

            Assert.IsTrue(Enumerable.SequenceEqual(expected, actual));
        }

        public static void AreNotEqual<T>(IEnumerable<T> notExpected, IEnumerable<T> actual)
        {
            // Although they are not expected to be equal, we expect them to be non-null.
            Assert.IsNotNull(actual);
            Assert.IsNotNull(notExpected);

            Assert.IsFalse(Enumerable.SequenceEqual(notExpected, actual));
        }
    }
}
