using System.Numerics;

namespace PrimalNumbers
{
    public static class PrimalBigInteger
    {
        public static bool IsPrime(BigInteger value)
        {
            return LowLevelPrimality.IsLowLevelPrime(value) && RabinMillerPrimality.IsMillerRabinPassed(value);
        }

        public static BigInteger GetPrime(int bitSize)
        {
            BigInteger result;
            do { result = RandomBigInteger.RandomIntegerWithBitSize(bitSize); } while (!IsPrime(result));
            return result;
        }
    }
}
