// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Describes a range of valid key sizes.
    /// </summary>
    public struct KeySizes : IEnumerable<int>, IEquatable<KeySizes>
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

        /// <summary>
        /// Checks value equality between two <see cref="KeySizes"/> values.
        /// </summary>
        /// <param name="first">One value to compare.</param>
        /// <param name="second">Another value to compare.</param>
        /// <returns><c>true</c> if the values are equal; <c>false</c> otherwise.</returns>
        public static bool operator ==(KeySizes first, KeySizes second) => first.Equals(second);

        /// <summary>
        /// Checks value inequality between two <see cref="KeySizes"/> values.
        /// </summary>
        /// <param name="first">One value to compare.</param>
        /// <param name="second">Another value to compare.</param>
        /// <returns><c>false</c> if the values are equal; <c>true</c> otherwise.</returns>
        public static bool operator !=(KeySizes first, KeySizes second) => !first.Equals(second);

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

        /// <inheritdoc/>
        public bool Equals(KeySizes other) => this.MaxSize == other.MaxSize && this.MinSize == other.MinSize && this.StepSize == other.StepSize;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is KeySizes other && this.Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => unchecked(this.MinSize + this.MaxSize + this.StepSize);
    }
}
