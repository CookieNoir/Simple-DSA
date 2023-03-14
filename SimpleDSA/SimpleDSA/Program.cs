using System;
using System.Text;
using System.Numerics;

namespace SimpleDSA
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Set bit size of p:");
            int bitSize = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine();
            DSA dsa = new DSA(bitSize);
            var (pBytes, qBytes, gBytes, yBytes) = dsa.GetPublicKey();
            Console.WriteLine("Public key (p, q, g, y) is:\n" +
                $"  p: {new BigInteger(pBytes, isUnsigned: true)}\n" +
                $"  q: {new BigInteger(qBytes, isUnsigned: true)}\n" +
                $"  g: {new BigInteger(gBytes, isUnsigned: true)}\n" +
                $"  y: {new BigInteger(yBytes, isUnsigned: true)}\n");
            byte[] xBytes = dsa.GetPrivateKey();
            Console.WriteLine("Private key (x) is:\n" +
                $"  x: {new BigInteger(xBytes, isUnsigned: true)}\n");

            Console.WriteLine("Set message:");
            byte[] message = Encoding.UTF8.GetBytes(Console.ReadLine());
            Console.WriteLine();

            var (rBytes, sBytes) = DSA.Sign(message, pBytes, qBytes, gBytes, xBytes);
            Console.WriteLine($"r: {BitConverter.ToString(rBytes).Replace("-", string.Empty).ToLower()}\n" +
                              $"s: {BitConverter.ToString(sBytes).Replace("-", string.Empty).ToLower()}\n");

            Console.WriteLine("Test, if (r, s) and (p, q, g, y) are correct");
            bool isCorrect = DSA.Verify(message, rBytes, sBytes, pBytes, qBytes, gBytes, yBytes);
            Console.WriteLine($"Verification result is (expecting true): {isCorrect}");
            Console.WriteLine();

            Console.WriteLine("Test, if r and s are swapped");
            isCorrect = DSA.Verify(message, sBytes, rBytes, pBytes, qBytes, gBytes, yBytes);
            Console.WriteLine($"Verification result is (expecting false): {isCorrect}");
            Console.WriteLine();

            Console.WriteLine("Test, if p, q, g, y are different");
            DSA dsa2 = new DSA(bitSize);
            (pBytes, qBytes, gBytes, yBytes) = dsa2.GetPublicKey();
            Console.WriteLine("Public key for  (p, q, g, y) is:\n" +
                $"  p: {new BigInteger(pBytes, isUnsigned: true)}\n" +
                $"  q: {new BigInteger(qBytes, isUnsigned: true)}\n" +
                $"  g: {new BigInteger(gBytes, isUnsigned: true)}\n" +
                $"  y: {new BigInteger(yBytes, isUnsigned: true)}\n");
            isCorrect = DSA.Verify(message, rBytes, sBytes, pBytes, qBytes, gBytes, yBytes);
            Console.WriteLine($"Verification result is (expecting false): {isCorrect}");
        }
    }
}
