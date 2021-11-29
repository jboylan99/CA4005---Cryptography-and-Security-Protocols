/*
ONLINE REFERENCES USED
https://www.baeldung.com/java-greatest-common-divisor
https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
*/

import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.io.IOException;

public class Assignment2 {

	public static void main(String args[])
	{
		String p = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd" +
					"ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc" +
					"8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
					"47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";

		String g = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
					"e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
					"1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
					"64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

		BigInteger modulus = new BigInteger(p, 16);
		BigInteger generator = new BigInteger(g, 16);
		BigInteger x = generateX(modulus);
		BigInteger y = generateY(generator, x, modulus);
		BigInteger k = generateK(modulus);
		BigInteger r = generateR(generator, k, modulus);
        BigInteger s;
        File input = new File("Assignment2.class");

        try
        {
            byte[] plaintext = Files.readAllBytes(input.toPath());

            byte[] message = hashFunction(plaintext);

            do
            {
                s = generateS(message, x, r, k, modulus);
            }
            while(s.equals(BigInteger.ZERO));

			verifySignature(r, s, generator, y, modulus, message);
        }
        catch(Exception e)
        {
            System.out.println(e);
        }

	}
 
    /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */
    
	public static BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus)
	{
		BigInteger y = generator.modPow(secretKey, modulus);
		writeToFile("y", y.toString(16));

		return y;
	}
	
    /* Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus */
       
	public static BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus)
	{
		BigInteger r = generator.modPow(k, modulus);
		writeToFile("r", r.toString(16));
		return r;
	}
	
    /* Method generateS generates the second part of the ElGamal signature from the given plaintext, secretKey, first signature part r, random value k and modulus */
       
    public static BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus)
    {
    	BigInteger hm = new BigInteger(plaintext);

        BigInteger m_1 = modulus.subtract(BigInteger.ONE);
    	// 
    	BigInteger kPowerMinusOne = calculateInverse(k, modulus); 

        // Breaking up "s = (H(m)-xr)k-1 (mod p-1)" into multiple parts to calculate s.
        BigInteger xr = secretKey.multiply(r); 
        BigInteger s1 = hm.subtract(xr).mod(m_1);
        BigInteger s2 = (k.modInverse(m_1));
        BigInteger s = s1.multiply(s2);
        s = s.mod(m_1);

    	writeToFile("s", s.toString(16));
    	return s;
    }
    
    /* Method calculateGCD returns the GCD of the given val1 and val2 */
    
    public static BigInteger calculateGCD(BigInteger val1, BigInteger val2)
    {
        // Base case.
        if(val2.equals(BigInteger.ZERO))
            return val1;

        // Recursion
        return calculateGCD(val2, val1.mod(val2));
    }
			
    /* Method calculateInverse returns the modular inverse of the given val using the given modulus */
    
    public static BigInteger calculateInverse(BigInteger val, BigInteger modulus)
    {
        BigInteger x = BigInteger.ONE;
        BigInteger y = BigInteger.ONE;
    	BigInteger gcd = extendedEuclideanAlgorithm(val, modulus, x, y);
        if(gcd.equals(BigInteger.ONE) != true)
        {
            return null;
        }
        else
        {    
            BigInteger inverse = (x.mod(modulus).add(modulus)).mod(modulus);
            return inverse;
        }
    }

    /* Method extendedEuclideanAlgorithm returns the GCD of the EEA. */

    public static BigInteger extendedEuclideanAlgorithm(BigInteger a, BigInteger b, BigInteger x, BigInteger y)
    {
        // Base case
        if(a.equals(BigInteger.ZERO))
        {
            x = BigInteger.ZERO;
            y = BigInteger.ONE;
            return b;
        }
        else
        {
            BigInteger x1 = BigInteger.ONE;
            BigInteger y1 = BigInteger.ONE;
            BigInteger gcd = extendedEuclideanAlgorithm(b.mod(a), a, x1, y1);

            x = y1.subtract(b.divide(a)).multiply(x1);
            y = x1;

            return gcd;
        }
        
    }

     /* Method generateX returns the secret key x and is randomly generated with a value between 0 and p-1 */
    
    public static BigInteger generateX(BigInteger p)
    {
   		Random r = new Random();
   		/*
        p is the highest limit, maxLen is the bit length of this value.
        high is the value of p-1.
        */
        BigInteger high = p.subtract(BigInteger.ONE);
    	int maxLen = high.bitLength();

        // A while loop that checks that the value of x is less than or equal to p-1.
        BigInteger x = new BigInteger(maxLen, r);
        while(x.compareTo(high) == 1)
            x = new BigInteger(maxLen, r);

        return x;
    }

    /* Method generateK returns k and is randomly generated with a value between 1 and p-1.
    It also must have a GCD of 1. */

    public static BigInteger generateK(BigInteger p)
    {
    	Random r = new Random();
   		// Set high and low limits to represent p-1 and 1.
    	BigInteger low = new BigInteger("1");
    	BigInteger high = p.subtract(low);
    	int maxLen = high.bitLength();
        BigInteger k;
        boolean gcd_check;
        BigInteger gcd;

        /* Do While loop that calculates k and its GCD.
        If GCD doesn't equal 1 or k isn't in the range, calculate k and GCD again. */
        do
        {
            k = new BigInteger(maxLen, r);
            gcd = calculateGCD(high, k);
            gcd_check = gcd.equals(BigInteger.ONE);
        }
        while(gcd_check == false || (k.compareTo(low) == -1 || k.compareTo(high) == 1));

        return k;
    }


    /* Method hashFunction hashes the input using hash function SHA-256 */

    public static byte[] hashFunction(byte[] plaintext)
    {
    	byte[] message;
    	try
    	{
        	MessageDigest md = MessageDigest.getInstance("SHA-256");
        	message = md.digest(plaintext);

        	return message;
        }
    	catch(NoSuchAlgorithmException e)
		{
			System.out.println("NoSuchAlgorithmException");
			e.printStackTrace();
		}
    	return null;
    }

    /* Method verifySignature checks that the digital signature is implemented correctly. */

    public static void verifySignature(BigInteger r, BigInteger s, BigInteger g, BigInteger y, BigInteger modulus, byte[] message)
    {
        System.out.println("Digital Signature using ElGamal");
        System.out.println("Verifying the Signature\n");
    	BigInteger p_1 = modulus.subtract(BigInteger.ONE);
    	BigInteger m = new BigInteger(message);

        // 0 < r < p
    	if(r.compareTo(BigInteger.ZERO) == 1 && r.compareTo(modulus) == -1)
    		System.out.println("R is valid with a value of " + r + "\n");
    	else
    		System.out.println("R is invalid with a value of " + r + "\n");

        // 0 < s < p-1
    	if(s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(p_1) == -1)
    		System.out.println("S is valid with a value of " + s + "\n");
    	else
    		System.out.println("S is invalid with a value of " + s + "\n");

        // g^H(m)(mod p) = (y^r)(r^s)(mod p)
    	BigInteger val1 = (g.modPow(m, modulus));
    	BigInteger val2 = (y.modPow(r, modulus)).multiply(r.modPow(s, modulus)).mod(modulus);
    	if(val1.equals(val2))
    		System.out.println("Both values are equal");
    	else
    		System.out.println("Not equal");
        System.out.println("g^H(m)(mod p): " + val1 + "\n");
        System.out.println("(y^r)(r^s)(mod p): " + val2);
    }
 	
    /* Method writeToFile creates a .txt file and adds contents to it */

 	public static void writeToFile(String filename, String contents)
	{
		try
		{
			File f = new File(filename + ".txt");
			f.createNewFile();
			FileWriter w = new FileWriter(f);
			w.write(contents);
			w.close();
		}
		catch(IOException e)
		{
			System.out.println("Error occurred: IOException");
			e.printStackTrace();
		}
	}
}