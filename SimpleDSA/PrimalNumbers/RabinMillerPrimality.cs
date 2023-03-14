using System.Numerics;

namespace PrimalNumbers
{
    // https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/
    internal static class RabinMillerPrimality
    {
        private static BigInteger _ExpMod(BigInteger basement, BigInteger exp, BigInteger mod)
        {
            if (exp == 0) return 1;
            if (exp % 2 == 0)
            {
                return (BigInteger.Pow(_ExpMod(basement, (exp / 2), mod),2)) % mod;
            }
            else
            {
                return (basement * _ExpMod(basement, (exp - 1), mod)) % mod;
            }
        }

        private static bool _IsTrialComposite(in BigInteger roundTester, in BigInteger evenComponent,
                                   BigInteger candidate, int maxDivisionsByTwo)
        {
            if (_ExpMod(roundTester, evenComponent, candidate) == 1)
                return false;
            for (int i = 0; i < maxDivisionsByTwo; i++)
            {
                if (_ExpMod(roundTester, (1 << i) * evenComponent, candidate) == candidate - 1)
                    return false;
            }
            return true;
        }

        internal static bool IsMillerRabinPassed(BigInteger candidate)
        {
            int maxDivisionsByTwo = 0;
            BigInteger evenComponent = candidate - 1;

            while (evenComponent % 2 == 0)
            {
                evenComponent >>= 1;
                maxDivisionsByTwo += 1;
            }

            int numberOfRabinTrials = 20;
            for (int i = 0; i < (numberOfRabinTrials); i++)
            {
                BigInteger roundTester = RandomBigInteger.RandomIntegerBelow(candidate);
                if (roundTester < 2) roundTester = 2;

                if (_IsTrialComposite(roundTester, evenComponent, candidate, maxDivisionsByTwo))
                    return false;
            }
            return true;
        }
    }
}
