namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;

    internal static class PclTestUtilities
    {
        internal static byte[] ToArray(this MemoryStream stream)
        {
            byte[] buffer = new byte[stream.Length];
            long oldPosition = stream.Position;
            stream.Position = 0;
            stream.Read(buffer, 0, buffer.Length);
            stream.Position = oldPosition;
            return buffer;
        }

        internal static string GetString(this Encoding encoding, byte[] buffer)
        {
            return encoding.GetString(buffer, 0, buffer.Length);
        }
    }
}
