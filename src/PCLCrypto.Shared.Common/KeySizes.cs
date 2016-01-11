// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System.Collections.Generic;

    /// <summary>
    /// Describes a range of valid key sizes.
    /// </summary>
    public struct KeySizes : IEnumerable<int>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeySizes"/> struct.
        /// </summary>
        /// <param name="minSize">The minimum key size (in bits).</param>
        /// <param name="maxSize">The maximum key size (in bits).</param>
        /// <param name="stepSize">The increment (in bits) between valid key sizes between <paramref name="minSize"/> and <paramref name="maxSize"/>.</param>
        public KeySizes(int minSize, int maxSize, int stepSize)
        {
            this.MaxSize = maxSize;
            this.MinSize = minSize;
            this.StepSize = stepSize;
        }

        /// <summary>
        /// Gets the maximum key size (in bits).
        /// </summary>
        public int MaxSize { get; }

        /// <summary>
        /// Gets the minimum key size (in bits).
        /// </summary>
        public int MinSize { get; }

        /// <summary>
        /// Gets the step interval (in bits) between valid key sizes in the range of
        /// <see cref="MinSize"/> to <see cref="MaxSize"/>.
        /// </summary>
        public int StepSize { get; }

        /// <inheritdoc />
        public IEnumerator<int> GetEnumerator()
        {
            if (this.StepSize == 0)
            {
                // This "range" is exactly one element big,
                // and the for loop below would run forever.
                yield return this.MinSize;
            }
            else
            {
                for (int size = this.MinSize; size <= this.MaxSize; size += this.StepSize)
                {
                    yield return size;
                }
            }
        }

        /// <inheritdoc />
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => this.GetEnumerator();
    }
}