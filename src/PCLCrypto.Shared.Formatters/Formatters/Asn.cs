// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// Encodes/decodes ASN.1 messages.
    /// </summary>
    /// <remarks>
    /// The ASN.1 format is documented here:
    /// http://en.wikipedia.org/wiki/X.690
    /// </remarks>
    internal static class Asn
    {
        /// <summary>
        /// The BER encoding Class of a data element.
        /// </summary>
        internal enum BerClass : byte
        {
            /// <summary>
            /// The type is native to ASN.1
            /// </summary>
            Universal = 0x00,

            /// <summary>
            /// The type is only valid for one specific application
            /// </summary>
            Application = 0x40,

            /// <summary>
            /// Meaning of this type depends on the context (such as within a sequence, set or choice)
            /// </summary>
            ContextSpecific = 0x80,

            /// <summary>
            /// Defined in private specifications
            /// </summary>
            Private = 0xC0,

            /// <summary>
            /// The set of bits that describe the class.
            /// </summary>
            Mask = 0xC0,
        }

        /// <summary>
        /// The BER encoding PC (primitive or constructed) of a data element.
        /// </summary>
        internal enum BerPC : byte
        {
            /// <summary>
            /// The content is primitive like an <see cref="BerTag.Integer"/>.
            /// </summary>
            Primitive = 0x00,

            /// <summary>
            /// The content holds type-length-value values like a <see cref="BerTag.Sequence"/>.
            /// </summary>
            Constructed = 0x20,

            /// <summary>
            /// The set of bits that describe the PC.
            /// </summary>
            Mask = 0x20,
        }

        /// <summary>
        /// The BER encoding Tag of a data element.
        /// </summary>
        internal enum BerTag : byte
        {
            /// <summary>
            /// Indicates that this is the end of the stream.
            /// </summary>
            EndOfContent = 0x0,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is an integer.
            /// </summary>
            Integer = 0x2,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is a bit string.
            /// </summary>
            BitString = 0x3,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is an octet string.
            /// </summary>
            OctetString = 0x4,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is null.
            /// </summary>
            Null = 0x5,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is an object identifier.
            /// </summary>
            ObjectIdentifier = 0x6,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is a sequence.
            /// </summary>
            Sequence = 0x10,

            /// <summary>
            /// Indicates that <see cref="DataElement.Content"/> is a set and set of.
            /// </summary>
            SetAndSetOf = 0x11,

            /// <summary>
            /// The set of bits that describe the tag.
            /// </summary>
            Mask = 0x1F,
        }

        /// <summary>
        /// Reads a sequence of ASN.1 elements from a stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>A sequence of elements.</returns>
        /// <remarks>
        /// The stream may not contain exclusively ASN.1 data.
        /// This method will read the stream exactly one element at a time,
        /// and the caller should only enumerate as many elements as are expected
        /// to avoid reading into other data.
        /// If the end of the stream is reached, the sequence terminates.
        /// </remarks>
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

                if (length > 8 * 1024)
                {
                    throw new FormatException("Invalid format or length too large.");
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

        /// <summary>
        /// Reads a sequence of ASN.1 elements from a stream.
        /// </summary>
        /// <param name="value">The buffer to read from.</param>
        /// <returns>A sequence of elements.</returns>
        /// <remarks>
        /// The stream may not contain exclusively ASN.1 data.
        /// This method will read the stream exactly one element at a time,
        /// and the caller should only enumerate as many elements as are expected
        /// to avoid reading into other data.
        /// If the end of the stream is reached, the sequence terminates.
        /// </remarks>
        internal static IEnumerable<DataElement> ReadAsn1Elements(byte[] value)
        {
            return ReadAsn1Elements(new MemoryStream(value));
        }

        /// <summary>
        /// Writes a single ASN.1 element to a stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="element">The data element.</param>
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
                for (int significancePosition = lengthOfLength - 1; significancePosition >= 0; significancePosition--)
                {
                    byte lengthOctet = (byte)(0xff & (element.Content.Length >> (8 * significancePosition)));
                    stream.WriteByte(lengthOctet);
                }
            }

            stream.Write(element.Content, 0, element.Content.Length);
        }

        /// <summary>
        /// Returns a buffer containing an encoded ASN.1 element.
        /// </summary>
        /// <param name="element">The data element.</param>
        /// <returns>The encoded ASN.1 element.</returns>
        internal static byte[] WriteAsn1Element(DataElement element)
        {
            var ms = new MemoryStream();
            ms.WriteAsn1Element(element);
            return ms.ToArray();
        }

        /// <summary>
        /// Returns a buffer containing encoded ASN.1 elements.
        /// </summary>
        /// <param name="elements">The data elements to encode.</param>
        /// <returns>The encoded ASN.1 elements.</returns>
        internal static byte[] WriteAsn1Elements(params DataElement[] elements)
        {
            var nestedStream = new MemoryStream();
            foreach (var element in elements)
            {
                nestedStream.WriteAsn1Element(element);
            }

            return nestedStream.ToArray();
        }

        /// <summary>
        /// Gets the minimum number of bytes required to represent an unsigned integer.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>The number of bytes [1-4] required to represent the value.</returns>
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

        /// <summary>
        /// Describes an individual ASN.1 element.
        /// </summary>
        internal struct DataElement
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="DataElement"/> struct.
            /// </summary>
            /// <param name="class">The class.</param>
            /// <param name="pc">The PC.</param>
            /// <param name="tag">The tag.</param>
            /// <param name="content">The content.</param>
            public DataElement(BerClass @class, BerPC pc, BerTag tag, byte[] content)
                : this()
            {
                this.Class = @class;
                this.PC = pc;
                this.Tag = tag;
                this.Content = content;
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="DataElement"/> struct.
            /// </summary>
            /// <param name="class">The class.</param>
            /// <param name="pc">The PC.</param>
            /// <param name="tag">The tag.</param>
            /// <param name="nestedElements">The content.</param>
            public DataElement(BerClass @class, BerPC pc, BerTag tag, params DataElement[] nestedElements)
                : this(@class, pc, tag, Asn.WriteAsn1Elements(nestedElements))
            {
            }

            /// <summary>
            /// Gets the class.
            /// </summary>
            public BerClass Class { get; private set; }

            /// <summary>
            /// Gets the PC.
            /// </summary>
            public BerPC PC { get; private set; }

            /// <summary>
            /// Gets the Tag.
            /// </summary>
            public BerTag Tag { get; private set; }

            /// <summary>
            /// Gets the Content.
            /// </summary>
            public byte[] Content { get; private set; }
        }
    }
}
