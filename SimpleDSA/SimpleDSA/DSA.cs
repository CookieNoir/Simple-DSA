using System.Numerics;
using System.Security.Cryptography;
using PrimalNumbers;

namespace SimpleDSA
{
    public class DSA
    {
        BigInteger _q;
        BigInteger _p;
        BigInteger _g;

        BigInteger _x;
        BigInteger _y;

        public DSA(int bitSize)
        {
            using SHA1 sha = SHA1.Create();
            _GenerateParams(bitSize, sha.HashSize);
            _GenerateKeys();
        }

        private void _GenerateParams(int L, int N)
        {
            BigInteger k;
            do
            {
                _q = PrimalBigInteger.GetPrime(N);
                k = RandomBigInteger.RandomIntegerWithBitSize(L - N);
                _p = (k * _q) + 1;
            }
            while (!PrimalBigInteger.IsPrime(_p));
            do
            {
                BigInteger h = 2 + RandomBigInteger.RandomIntegerBelow(_p - 3);
                _g = BigInteger.ModPow(h, k, _p);
            }
            while (_g == 1);
        }

        private void _GenerateKeys()
        {
            _x = 1 + RandomBigInteger.RandomIntegerBelow(_q - 1);
            _y = BigInteger.ModPow(_g, _x, _p);
        }

        public byte[] GetPrivateKey()
        {
            return _x.ToByteArray(isUnsigned: true);
        }

        public (byte[], byte[], byte[], byte[]) GetPublicKey() // returns (p, q, g, y)
        {
            return (_p.ToByteArray(isUnsigned: true),
                    _q.ToByteArray(isUnsigned: true),
                    _g.ToByteArray(isUnsigned: true),
                    _y.ToByteArray(isUnsigned: true));
        }

        private static BigInteger _ModInverse(BigInteger a, BigInteger b) // based on extended Euclidean Algorithm
        {         
            BigInteger x = 1, x1 = 0, a1 = a, b1 = b;
            while (b1 != 0)
            {
                BigInteger q = a1 / b1;

                BigInteger temp = x;
                x = x1;
                x1 = temp - q * x1;

                temp = a1;
                a1 = b1;
                b1 = temp - q * b1;
            }
            return x;
        }

        public static (byte[], byte[]) Sign(byte[] message, byte[] pBytes, byte[] qBytes, byte[] gBytes, byte[] xBytes) // returns (r, s)
        {
            BigInteger p = new BigInteger(pBytes, isUnsigned: true);
            BigInteger q = new BigInteger(qBytes, isUnsigned: true);
            BigInteger g = new BigInteger(gBytes, isUnsigned: true);
            BigInteger x = new BigInteger(xBytes, isUnsigned: true);

            BigInteger h = new BigInteger(SHA1.Create().ComputeHash(message), isUnsigned: true);
            BigInteger k, r, s;
            do
            {
                do
                {
                    k = 1 + RandomBigInteger.RandomIntegerBelow(q - 1);
                    r = BigInteger.ModPow(g, k, p) % q;
                }
                while (r == 0);

                BigInteger inverseK = (_ModInverse(k, q) + q) % q;
                s = ((h + x * r) * inverseK) % q;
            }
            while (s == 0);
            return (r.ToByteArray(isUnsigned: true), s.ToByteArray(isUnsigned: true));
        }

        public static bool Verify(byte[] message, byte[] rBytes, byte[] sBytes, byte[] pBytes, byte[] qBytes, byte[] gBytes, byte[] yBytes)
        {
            BigInteger r = new BigInteger(rBytes, isUnsigned: true);
            BigInteger s = new BigInteger(sBytes, isUnsigned: true);
            BigInteger q = new BigInteger(qBytes, isUnsigned: true);

            if (r <= 0 || r >= q || s <= 0 || s >= q) return false;

            BigInteger p = new BigInteger(pBytes, isUnsigned: true);
            BigInteger g = new BigInteger(gBytes, isUnsigned: true);
            BigInteger y = new BigInteger(yBytes, isUnsigned: true);

            BigInteger h = new BigInteger(SHA1.Create().ComputeHash(message), isUnsigned: true);
            BigInteger w = (_ModInverse(s, q) + q) % q;
            BigInteger u1 = (h * w) % q;
            BigInteger u2 = (r * w) % q;
            BigInteger v = (BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(y, u2, p)) % p % q;
            return v == r;
        }
    }
}
