import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Formatter;
import java.util.Scanner;
import java.io.File;
import java.util.NoSuchElementException;
import java.util.Random;
import java.security.SecureRandom;
import java.lang.Math;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Generator
{
	static Formatter outfile;
	static Scanner input;
	static Parameters p = new Parameters ();
	
	public static void createTextFile (String filename)
	{
		// create files to store alice's and bob's info
		try
		{
			outfile = new Formatter (filename);
		}
		catch (FileNotFoundException f)
		{
			System.err.println ("File could not be opened for creation");
			System.exit (1);
		}
		catch (SecurityException s)
		{
			System.err.println ("Write permission denied");
			System.exit (1);
		}
		
		
		outfile.format ("%s%n", p);
		
		if (outfile != null)
		{
			outfile.close ();
			System.out.println ("Parameters for \"" + filename + "\" have been created.");
		}
	}
	
	public static void generateKey (String filename, String outputfile)
	{
		String pwd = "";
		BigInteger prime = BigInteger.ZERO;
		BigInteger g = BigInteger.ZERO;
		BigInteger temp = BigInteger.ZERO;
		
		try
		{
			input = new Scanner (new File (filename));
		}
		catch (IOException e)
		{
			System.err.println ("Error in IO");
			System.exit (1);
		}
		
		try
		{
			while (input.hasNext ())
			{
				pwd = input.nextLine();
				prime = input.nextBigInteger ();
				g = input.nextBigInteger ();
				temp = input.nextBigInteger (); // Alice's secret key
			}
		}
		catch (NoSuchElementException e)
		{
			System.err.println ("No such element exception caught");
			System.exit (1);
		}  
		
		if (input != null)
		{
			input.close ();
		}
		
		temp = p.generateSecretKey (prime); // update to Bob's secret key
		
		// create files to store bob's info
		try
		{
			outfile = new Formatter (outputfile);
		}
		catch (FileNotFoundException f)
		{
			System.err.println ("File could not be opened for creation");
			System.exit (1);
		}
		catch (SecurityException s)
		{
			System.err.println ("Write permission denied");
			System.exit (1);
		}
		
		outfile.format ("%s%n%d%n%d%n%d", pwd, prime, g, temp);
		
		if (outfile != null)
		{
			outfile.close ();
			System.out.println ("Secret keys have been generated.");
		}
	}
	
	public static void main (String [] args)
	{
		createTextFile ("Alice/vault.txt");
		
		generateKey ("Alice/vault.txt", "Bob/vault.txt");
		
	}
}

// create parameters objects for alice's and bob's info
class Parameters
{
	private String password;
	private BigInteger p;
	private BigInteger g;
	private BigInteger secretKey;
	
	public Parameters ()
	{
		this.password = getPassword();
		this.p = getPrime();
		PrimitiveRoot gen = new PrimitiveRoot ();
		this.g = BigInteger.valueOf (gen.findPrimitive (this.p));
		this.secretKey = generateSecretKey (this.p);
		
	}
	
	public String getPassword ()
	{
		String pw = "";
		
		Random r = new Random ();
		int temp;
		String tempstr;
		
		for (int i = 0; i < 6; i++)
		{
			temp = r.nextInt (10);
			tempstr = Integer.toString (temp);
			pw = pw.concat (tempstr);
		}
		
		return pw;
	}
	
	public static boolean isPrime (BigInteger prime)
	{
		return prime.isProbablePrime (1); 
	}
	
	public BigInteger getPrime ()
	{
		// A Random class has only 48 bits where as SecureRandom can have up to 128 bits. 			
		// So the chances of repeating in SecureRandom are smaller.
		SecureRandom random = new SecureRandom();
		BigInteger p = BigInteger.ZERO;  
		BigInteger min = new BigInteger ("2147483648"); //  2,147,483,647 + 1 (must be at least 32 bits)
		BigInteger max = new BigInteger ("9999999999");
		BigInteger safePrime = BigInteger.ZERO;
		boolean sprimeOK;
		BigInteger two = new BigInteger ("2");
		do
		{
			sprimeOK = false;
			safePrime = new BigInteger (max.bitLength(), random);
			
			// if it's bigger than the specified max
			while (safePrime.compareTo (max) >= 0 || safePrime.compareTo (min) <= 0)
			{
				safePrime = new BigInteger (max.bitLength(), random);	
			}
			
			if (isPrime (safePrime))
			{
				p = (safePrime.subtract (BigInteger.ONE)).divide (two); // safeprime = 2p + 1 -> p?
				if (isPrime (p))
				{
					sprimeOK = true;
				}
			}
			
		} while (sprimeOK == false);
		
		return safePrime;
	}
	
	public static BigInteger generateSecretKey (BigInteger sPrime)
	{
		SecureRandom random = new SecureRandom();
		BigInteger secret;
		BigInteger max = sPrime.subtract (BigInteger.ONE);
		
		// Alice chooses x<q-1as her private key and calculates y=gx mod q.
		secret = new BigInteger (max.bitLength(), random);
		
		// if it's bigger than or equal to the specified max 
		while (secret.compareTo (max) > 0)
		{
			secret = new BigInteger (max.bitLength(), random);	
		}
		
		// e.g. (10) -> 0-9
		// e.g. (10) + 1 -> 1-10
		// e.g. (10-1) + 1 -> 1-9
		// e.g. (10-2) + 1 -> 1-8
		return secret;
	}
	
	public String toString ()
	{
		return String.format ("%s%n%d%n%d%n%d", password, p, g, secretKey);
	}
}
