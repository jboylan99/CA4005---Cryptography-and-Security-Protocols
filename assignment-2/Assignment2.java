/*
ONLINE REFERENCES USED
https://www.baeldung.com/java-greatest-common-divisor
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
			BigInteger generator = new BigInteger(p, 16);
			BigInteger x = generateX(p);
			System.out.println("X: " + x);
			BigInteger y = generateY(generator, x, modulus);
			BigInteger k = generateK(p);
			BigInteger r = generateR(generator, k, modulus);

			String input = "kgjshgjasofjao;bijborejgo;aga";
			byte[] plaintext = hashFunction(input);
			BigInteger s = generateS(plaintext, x, r, k, modulus);

			verifySignature(r, s, generator, y, modulus, plaintext);

		}
	 
        /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */
        
		public static BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus)
		{
			BigInteger y = generator.modPow(secretKey, modulus);
			System.out.println(secretKey + " mod " + modulus);
			System.out.println("Y: "+ y);
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
        	BigInteger one = new BigInteger("1");
        	BigInteger m = new BigInteger(plaintext);
        	// s = (H(m)-xr)k-1 (mod p-1)
        	BigInteger kMinusOne = calculateInverse(k, modulus); 

        	BigInteger s = ((m.subtract(secretKey.multiply(r))).multiply(k)).mod(modulus.subtract(one));
        	System.out.println("S: " + s);
        	writeToFile("s", s.toString(16));
        	return s;
        }
        
        /* Method calculateGCD returns the GCD of the given val1 and val2 */
        
        public static BigInteger calculateGCD(BigInteger val1, BigInteger val2)
        {
        	BigInteger zero = new BigInteger("0"); 
        	if (val2.compareTo(BigInteger.ZERO) == 0)
        		return val1;
        	else
        		return calculateGCD(val2, val1.mod(val2));
        }
				
        /* Method calculateInverse returns the modular inverse of the given val using the given modulus */
        
        public static BigInteger calculateInverse(BigInteger val, BigInteger modulus)
        {
        	return val;
        }


         /* Method generateX returns the secret key x and is randomly generated with a value between 1 and p-1 */
        
        public static BigInteger generateX(String p)
        {
       		Random r = new Random();
       		// Set high and low limits to represent p-1 and 1.
        	BigInteger low = new BigInteger("1");
        	BigInteger pBigInt = new BigInteger(p, 16);
        	BigInteger high = pBigInt.subtract(low);
        	// diff is the difference between high and low.
        	BigInteger diff = high.subtract(low);
        	int maxLen = high.bitLength();

        	/* x will be a random BigInteger.
			If x is less than the lowest value, add low to x.
			If x is greater than or equal to the difference,
			add low to x modulo diff.
        	*/
        	BigInteger x = new BigInteger(maxLen, r);
      		if (x.compareTo(low) < 0)
         		x = x.add(low);
      		if (x.compareTo(diff) >= 0)
         		x = x.mod(diff).add(low);

        	return x;
        }
        public static BigInteger generateK(String p)
        {
        	Random r = new Random();
       		// Set high and low limits to represent p-1 and 0.
        	BigInteger low = new BigInteger("0");
        	BigInteger pMinusOne = new BigInteger("1");
        	BigInteger pBigInt = new BigInteger(p, 16);
        	BigInteger high = pBigInt.subtract(pMinusOne);
        	// diff is the difference between high and low.
        	BigInteger diff = high.subtract(low);
        	int maxLen = high.bitLength();

        	BigInteger k = new BigInteger(maxLen, r);
      		if (k.compareTo(low) <= 0)
         		 k= k.add(low);
      		if (k.compareTo(diff) >= 0)
         		k = k.mod(diff).add(low);

         	BigInteger gcd = calculateGCD(k, high);
         	while (true)
         	{
	         	if (gcd.compareTo(BigInteger.ONE) == 1)
	         	{
	         		System.out.println("K: " + k);
					return k;
				}
				else
				{
					gcd = calculateGCD(k, high);
				}
			}
        }

        public static byte[] hashFunction(String plaintext)
        {
        	byte[] message;
        	try
        	{
	        	MessageDigest md = MessageDigest.getInstance("SHA-256");
	        	md.update(plaintext.getBytes());
	        	message = md.digest();

	        	return message;
	        }
        	catch(NoSuchAlgorithmException e)
			{
				System.out.println("NoSuchAlgorithmException");
				e.printStackTrace();
			}

        	return null;
        }

        public static void verifySignature(BigInteger r, BigInteger s, BigInteger g, BigInteger y, BigInteger modulus, byte[] plaintext)
        {
        	BigInteger p_1 = modulus.subtract(BigInteger.ONE);
        	BigInteger m = new BigInteger(plaintext);
        	System.out.println("M " + m);

        	if(r.compareTo(BigInteger.ZERO) == 1 && r.compareTo(modulus) == -1)
        		System.out.println("r is valid with a value of " + r);
        	else
        		System.out.println("r is invalid with a value of " + r);

        	if(s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(p_1) == -1)
        		System.out.println("s is valid with a value of " + s);
        	else
        		System.out.println("s is invalid with a value of " + s);

        	BigInteger val1 = (g.pow(m.intValue())).mod(modulus);
        	BigInteger val2 = ((y.pow(r.intValue())).multiply(r.pow(s.intValue()))).mod(modulus);
        	if(val1.equals(val2))
        		System.out.println("Equal");
        	else
        		System.out.println("Not equal");
        }
	 	
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