/*
ONLINE REFERENCES USED
https://www.baeldung.com/java-cipher-class
https://tutorialspoint.dev/algorithm/mathematical-algorithms/modular-exponentiation-power-in-modular-arithmetic
https://stackoverflow.com/questions/2817752/java-code-to-convert-byte-to-hexadecimal
https://www.javacodegeeks.com/2018/03/aes-encryption-and-decryption-in-javacbc-mode.html
https://www.baeldung.com/java-byte-arrays-hex-strings
*/

import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.io.IOException;
import java.util.*;
import java.lang.Integer.*; 

public class Assignment1 implements Assignment1Interface {

 	public static void main(String[] args)
	{
		String password = "4Q5Y(xMD{3`QgPv;";
		// Password as byte array.
		byte[] p = password.getBytes();

		BigInteger exponent = new BigInteger("65537");
		String hexStr = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
		BigInteger modulus = new BigInteger(hexStr, 16);

		File input = new File(args[0]);
		byte[] iv = generateIV();
		byte[] salt = generateSalt();
		byte[] key = generateKey(password, generateSalt());
		try
		{
			byte[] plaintext = Files.readAllBytes(input.toPath());
			String pt = byteArrayToHex(plaintext);
			// Writing contents of plaintext to file for testing purposes.
			// writeToFile("plaintext", pt);
			byte[] ciphertext = encryptAES(plaintext, iv, key);
			//decryptAES used for testing purposes.
			decryptAES(ciphertext, iv, key);
		}
		catch(IOException e)
		{
			e.printStackTrace();	
		}

		encryptRSA(p, exponent, modulus);
	}

	/* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */

	public static byte[] generateKey(String password, byte[] salt)
	{
		// Encoding the password using UTF-8.
		byte[] pass = password.getBytes(StandardCharsets.UTF_8);
		
		// Concatenating the password and salt byte arrays.
		byte[] key = new byte[pass.length + salt.length];
		System.arraycopy(pass, 0, key, 0, pass.length);
		System.arraycopy(salt, 0, key, pass.length, salt.length);
		
		try
		{
			// SHA-256 Hashing.
			MessageDigest md = MessageDigest.getInstance("SHA-256");

			// Hashing it 200 times.
			for(int i = 0; i < 200; i++)
			{
				key = md.digest(key);
			}
			// Reset MessageDigest because it isn't thread-safe.
			md.reset();
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("NoSuchAlgorithmException");
			e.printStackTrace();
		}
		return key;
	}
	
    /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
       
	public static byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key)
	{
		try
		{
			// Create key and IV to be used to encrypt plaintext.
			SecretKeySpec k = new SecretKeySpec(key, "AES");
			IvParameterSpec i = new IvParameterSpec(iv);
			// AES CBC cipher with no padding initially (this will be added later).
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, k, i);
			int lenInput = plaintext.length;
			int blockSize = cipher.getBlockSize();
			// Adding padding if necessary.
			byte[] paddedMessage = addPadding(plaintext, blockSize);
			byte[] encryptedMessage = cipher.doFinal(paddedMessage);

			// Byte array becomes hex string.
			String encryption = byteArrayToHex(encryptedMessage);
			// Printing here to output to command line so it can be written to encryption.txt.
    		System.out.println(encryption);

    		return encryptedMessage;
		}
		catch(NoSuchPaddingException e)
		{
			System.out.println("NoSuchPaddingException");
			e.printStackTrace();
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("NoSuchAlgorithmException");
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e)
		{
        	e.printStackTrace();
    	} 
    	catch (InvalidKeyException e)
    	{
        	e.printStackTrace();
   	 	}
   	 	catch (IllegalBlockSizeException e)
    	{
        	e.printStackTrace();
   	 	}
   	 	catch(BadPaddingException e)
		{
			System.out.println("BadPaddingException");
			e.printStackTrace();
		}
		return null;
	}
	
    /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
    
    public static byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key)
    {
    	try
    	{
    		// Similar to encryptAES, but in reverse.
        	SecretKeySpec k = new SecretKeySpec(key, "AES");
			IvParameterSpec i = new IvParameterSpec(iv);

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        	cipher.init(Cipher.DECRYPT_MODE, k, i);
        	byte[] original = cipher.doFinal(ciphertext);
        	String decrypt = byteArrayToHex(original);
        	// The following line is used for testing purposes to compare it to the plaintext.
        	// writeToFile("decrypt", decrypt);
    	}
    	catch(NoSuchAlgorithmException e)
		{
			System.out.println("NoSuchAlgorithmException");
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e)
		{
        	e.printStackTrace();
    	} 
    	catch (InvalidKeyException e)
    	{
        	e.printStackTrace();
   	 	}
   	 	catch (IllegalBlockSizeException e)
    	{
        	e.printStackTrace();
   	 	}
   	 	catch(BadPaddingException e)
		{
			System.out.println("BadPaddingException");
			e.printStackTrace();
		}
		catch(NoSuchPaddingException e)
		{
			System.out.println("NoSuchPaddingException");
			e.printStackTrace();
		}
   		return key;
    }    
			
    /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
    
    public static byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus)
    {
    	// Change plaintext to type BigInteger.
    	BigInteger base = new BigInteger(plaintext);
    	// Use modExp to calculate modular exponentiation.
    	BigInteger encrypted = modExp(base, exponent, modulus);
    	// Change BigInteger to byte array, avoiding leading zero if necessary.
    	byte[] rsa = encrypted.toByteArray();
    	byte[] removeZero = new byte[rsa.length - 1];
    	// If there is a leading zero, remove it. 
    	if (rsa[0] == 0)
    	{
    		System.arraycopy(rsa, 1, removeZero, 0, rsa.length);

    		// Change byte array to hex string in order to write to password.txt.
    		String removeZeroHex = byteArrayToHex(removeZero);
    		writeToFile("password", removeZeroHex);
    		return removeZero;
    	}
    	// Else, return the rsa byte array.
    	else
    	{		
	    	// Change byte array to hex string in order to write to password.txt.
	    	String rsaHex = byteArrayToHex(rsa);
	    	writeToFile("Password", rsaHex);
	    	return rsa;
	    }
    }
 
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
    
    public static BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus)
    {
    	// Set default value to 1.
    	BigInteger y = new BigInteger("1");
    	// Change exponent to string and use a for loop for the square and multiply algorithm.
    	String binaryExp = exponent.toString(2);
    	for(int i = 0; i < binaryExp.length(); i++)
    		// If the value of the bit is 1, multiply base by y.
    		if(binaryExp.charAt(i) == '1')
    			y = (y.multiply(base)).mod(modulus);
    		// Then square the base.
    		base = (base.multiply(base)).mod(modulus);
    	// Return value.
    	return base;
    }
    
    // Method to generate salt and write to salt.txt.

	public static byte[] generateSalt()
	{
		// Generate 128-bit salt.
		SecureRandom random = new SecureRandom();
		byte[] s = new byte[16];
		random.nextBytes(s);
		String salt = byteArrayToHex(s);
		writeToFile("Salt", salt);
		return s;
	}

	// Method to generate IV and write to IV.txt.

	public static byte[] generateIV()
	{
		// Generate 128-bit IV.
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		String iVector = byteArrayToHex(iv);
		writeToFile("IV", iVector);
		return iv;
	}

	// Method to add padding to message.

	public static byte[] addPadding(byte[] message, int blockSize)
	{
		int len = message.length;
		int difference = len % blockSize;

		int bytesToAdd = 16 - (difference);
		int totalLen = len + bytesToAdd;
		byte[] padding = new byte[totalLen];
		System.arraycopy(message, 0, padding, 0, len);
		padding[len] = (byte)0x80;
		for(int i = len + 1; i < padding.length; i++)
			padding[i] = (byte)0;
		return padding;
	}

    // Method to convert byte arrays to hexidecimal.

	public static String byteArrayToHex(byte[] a)
	{
	   StringBuilder sb = new StringBuilder(a.length * 2);
	   for(byte b: a)
	      sb.append(String.format("%02x", b));
	   return sb.toString();
	}

	// Method to write to text files.

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