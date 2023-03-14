using System;
using System.Collections;
using System.Numerics;

namespace PrimalNumbers
{
    public static class RandomBigInteger
    {
        public static BigInteger RandomIntegerBelow(BigInteger N)
        {
            byte[] bytes = N.ToByteArray();
            BigInteger R;
            Random random = new Random();
            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] &= 0x7F; // negative sign bit
                R = new BigInteger(bytes);
            } while (R >= N);

            return R;
        }

        public static BigInteger RandomIntegerWithBitSize(int bitSize)
        {
            int extendedBitSize = bitSize + (8 - bitSize % 8);
            BitArray bits = new BitArray(extendedBitSize);
            bits[bitSize - 1] = true;
            byte[] bytes = new byte[extendedBitSize / 8];
            bits.CopyTo(bytes, 0);
            BigInteger minValue = new BigInteger(bytes);
            return minValue + RandomIntegerBelow(minValue);
        }
    }
}
