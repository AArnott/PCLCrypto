namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    // http://en.wikipedia.org/wiki/X.690
    internal static class Asn
    {
        internal static IEnumerable<DataElement> ReadAsn1Elements(this Stream stream)
        {
            Requires.NotNull(stream, "stream");

            do
            {
                int b = stream.ReadByte();
                if (b == -1)
                {
                    yield break;
                }

                BerClass clazz = (BerClass)b & BerClass.Mask;
                BerPC pc = (BerPC)b & BerPC.Mask;
                BerTag tag = (BerTag)b & BerTag.Mask;

                uint length = 0;
                b = stream.ReadByte();
                if ((b & 0x80) == 0x80)
                {
                    // long form
                    byte lengthOfLength = (byte)(b & 0x7F);
                    for (int i = 0; i < lengthOfLength; i++)
                    {
                        // big endian
                        b = stream.ReadByte();
                        length <<= 8;
                        length += (uint)b;
                    }
                }
                else
                {
                    // short form.
                    length = (uint)b;
                }

                byte[] content = new byte[length];
                int bytesRead = stream.Read(content, 0, (int)length);
                if (bytesRead != length)
                {
                    throw new ArgumentException("Unexpected end of stream.");
                }

                yield return new DataElement(clazz, pc, tag, content);
            }
            while (true);
        }

        internal static void WriteAsn1Element(this Stream stream, DataElement element)
        {
            Requires.NotNull(stream, "stream");

            byte identifier = (byte)((byte)element.Class | (byte)element.PC | (byte)element.Tag);
            stream.WriteByte(identifier);

            if (element.Content.Length < 128)
            {
                // use short form
                stream.WriteByte((byte)element.Content.Length);
            }
            else
            {
                // use long form
                byte lengthOfLength = GetMinimumBytesRequiredToRepresent((uint)element.Content.Length);
                stream.WriteByte((byte)(0x80 + lengthOfLength));

                // We must write this out as big endian. We use an endian-agnostic way of reading out the integer.
                for (int significancePosition = 4 - lengthOfLength; significancePosition >= 0; significancePosition--)
                {
                    byte lengthOctet = (byte)(0xff & (element.Content.Length >> (8 * significancePosition)));
                    stream.WriteByte(lengthOctet);
                }
            }

            stream.Write(element.Content, 0, element.Content.Length);
        }

        private static byte GetMinimumBytesRequiredToRepresent(uint value)
        {
            if (value > 0xffffff)
            {
                return 4;
            }
            else if (value > 0xffff)
            {
                return 3;
            }
            else if (value > 0xff)
            {
                return 2;
            }
            else
            {
                return 1;
            }
        }

        internal struct DataElement
        {
            public DataElement(BerClass @class, BerPC pc, BerTag tag, byte[] content)
                : this()
            {
                this.Class = @class;
                this.PC = pc;
                this.Tag = tag;
                this.Content = content;
            }

            public BerClass Class { get; private set; }
            public BerPC PC { get; private set; }
            public BerTag Tag { get; private set; }
            public byte[] Content { get; private set; }
        }

        internal enum BerClass : byte
        {
            Universal = 0x00,
            Application = 0x40,
            ContextSpecific = 0x80,
            Private = 0xC0,

            Mask = 0xC0,
        }

        internal enum BerPC : byte
        {
            Primitive = 0x00,
            Constructed = 0x20,

            Mask = 0x20,
        }

        internal enum BerTag : byte
        {
            Integer = 0x2,
            BitString = 0x3,
            Null = 0x5,
            ObjectIdentifier = 0x6,
            Sequence = 0x10,

            Mask = 0x1F,
        }
    }
}
