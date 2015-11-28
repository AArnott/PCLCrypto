// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System.Collections.Generic;

    /// <summary>
    /// Describes a range of valid key sizes.
    /// </summary>
    public struct KeySizes
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeySizes"/> struct.
        /// </summary>
        /// <param name="minSize">The minimum key size.</param>
        /// <param name="maxSize">The maximum key size.</param>
        /// <param name="stepSize">The increment between valid key sizes between <paramref name="minSize"/> and <paramref name="maxSize"/>.</param>
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
    }
}