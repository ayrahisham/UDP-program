// Nur Suhaira Bte Badrul Hisham
// Assignment 1
// 5841549

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Date;

import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.NoSuchElementException;
import java.io.IOException;

import java.math.BigInteger;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

public class Host 
{

	private static final int BYTESIZE = 4096;
	private static final int PORTNUMBER = 49445;
	private static final String VAULT = "vault.txt";

	private static DatagramSocket host_socket;
	private static DatagramPacket incoming_packet;
	private static DatagramPacket outgoing_packet;
	private static Scanner file;
	
	private static byte [] incoming_buffer;
	private static byte [] outgoing_buffer;

	private static String shared_session_key;
	
	public static boolean readFile (String filename)
	{
		try 
		{
			file = new Scanner (new File (filename));
		} 
		catch (FileNotFoundException ex) 
		{
			System.out.println ("Unable to detect file...");
			return false;
		}
		
		return true;
	} 
  	
  	// not running this func.
	public static BigInteger discreteLogarithm (BigInteger bigH, BigInteger bigG, BigInteger bigP)
	{
		for (BigInteger y = BigInteger.ONE; y.compareTo (bigP) < 0 ; y = y.add (BigInteger.ONE))
		{
			if (bigG.modPow (y, bigP).equals (bigH))
			{
				return y;
			}
		}
		
		return BigInteger.ZERO;
	}
	  
	
	public static String computeSessionKey (BigInteger h, BigInteger x, BigInteger p)
	{
		BigInteger sum = h.modPow (x, p);
		String sum_str = sum.toString ();
		
		return hashing (sum_str);
	}
	
	// Source: https://www.geeksforgeeks.org/sha-1-hash-in-java/
	public static String hashing (String input) 
    	{ 
        	try 
        	{ 
		    // getInstance() method is called with algorithm SHA-1 
		    MessageDigest md = MessageDigest.getInstance("SHA-1"); 
	  
		    // digest() method is called 
		    // to calculate message digest of the input string 
		    // returned as array of byte 
		    byte[] messageDigest = md.digest(input.getBytes()); 
	  
		    // Convert byte array into signum representation 
		    BigInteger no = new BigInteger(1, messageDigest); 
	  
		    // Convert message digest into hex value 
		    String hashtext = no.toString(16); 
	  
		    // Add preceding 0s to make it 32 bit 
		    while (hashtext.length() < 32) { 
		        hashtext = "0" + hashtext; 
		    } 
  
		    // return the HashText 
		    return hashtext; 
		} 
	  
		// For specifying wrong message digest algorithms 
		catch (NoSuchAlgorithmException e) 
		{ 
		    throw new RuntimeException (e); 
		} 
	} 
	
	public static void main (String [] args)
	{
		System.out.print("\033[H\033[2J");
		String password = "";
		BigInteger bigP = BigInteger.ZERO;
		BigInteger bigG = BigInteger.ZERO;
		BigInteger bigX = BigInteger.ZERO;
		BigInteger chostSK; // computation of g^x mod p
		byte buffer [] = new byte [BYTESIZE];
		String clientSK = "";
		
		if (readFile (VAULT))
		{	
			System.out.println ("Begin processing of " + VAULT);
			
			// Process the input file
			try
			{	
				while (file.hasNext ())
				{
					// retreiving parameters password, p, g, SK
					password = file.nextLine ();
					bigP = file.nextBigInteger ();
					bigG = file.nextBigInteger ();
					bigX = file.nextBigInteger ();
				}
			}
			catch (NoSuchElementException e)
			{
				System.out.println ("No such element exception caught in " + VAULT);
				System.exit (1);
			}
			
			System.out.println ("Processing of " + VAULT + " completed\n");
			
			try 
			{
				System.out.println("Waiting for new connection request...");

				host_socket = new DatagramSocket (PORTNUMBER);
				incoming_packet = new DatagramPacket (new byte [BYTESIZE], BYTESIZE);

				// Host receives a connection request from client
				host_socket.receive (incoming_packet);
				String message = new String (incoming_packet.getData(), 0, incoming_packet.getLength());
				System.out.println ("IP: " + incoming_packet.getAddress() + "\n" + 
						    "Port: " + incoming_packet.getPort() + "\n" +
						    "Message from Client: \n" + message + "\n");
				
				System.out.println ("Preparing packet for client...");
				
		    		// computes g^x mod p, encrypts it using RC4, and sends the ciphertext to Client (using SK)
				chostSK = bigG.modPow (bigX, bigP);
				String chostSK_str = chostSK.toString ();
		    		
		    		// create rc4 with password
				RC4 rc4E = new RC4 (password.getBytes ());
				
				// encrypt using rc4
				buffer = rc4E.encrypt (chostSK_str.getBytes()); 
				
				// using the same client's address and port receiving from request
				outgoing_packet = new DatagramPacket (buffer, 0, buffer.length, incoming_packet.getAddress(), incoming_packet.getPort());
				
				host_socket.send (outgoing_packet);
				System.out.println ("Sending packet to Client..\n");
				
				// retrieve client's SK
				host_socket.receive (incoming_packet);
				System.out.println ("Receiving packet from Client...\n");
				
				try
				{
					// decrypting client's SK from packet
					System.out.println ("Decrypting packet...");
					incoming_buffer = incoming_packet.getData ();
					RC4 rc4D = new RC4 (password.getBytes());
					buffer = rc4D.decrypt (incoming_buffer);
					String buffer_str = new String (buffer, 0, incoming_packet.getLength());
					BigInteger h = new BigInteger (buffer_str);
				
					/*
					// Find the unique number a<p such that h = g^y mod p
					BigInteger y = discreteLogarithm (h, bigG, bigP);
					*/
				
					// make sure y is not 0
					// compute session key
					// g^x mod p = h^y mod p = g^(xy) mod p	
					String K = computeSessionKey (h, bigX, bigP);
					System.out.println ("Session key: " + K);
					System.out.println ("Session key generated successfully...\n");
				
					// send confirmation to Client
					RC4 rc4E2 = new RC4 (password.getBytes());
					outgoing_buffer = rc4E2.encrypt (new String ("Established").getBytes());
					outgoing_packet = new DatagramPacket(outgoing_buffer, 0, outgoing_buffer.length, incoming_packet.getAddress(), incoming_packet.getPort());
					host_socket.send(outgoing_packet);
				
					// Establishes session with Client
					System.out.println ("Established connection with Bob - IP: " + incoming_packet.getAddress() + ", Port: " + incoming_packet.getPort() + "\n");
					System.out.println ("Waiting for incoming message...\n");
				
					String Hprime = "";
					String H = "";
					String response = "";
					String host_msg;
					SessionWindow session = new SessionWindow ();
				
					while (true)
					{	
						host_msg = "";
						host_socket.receive (incoming_packet);
						incoming_buffer = incoming_packet.getData ();
					
						// runs the decryption algorithm to obtain M||H = DK(C). 
						RC4 rc4d = new RC4 (K.getBytes());
						buffer = rc4d.decrypt (incoming_buffer);
						buffer_str = new String (buffer, 0, incoming_packet.getLength());
					
						// extract M from M||H
						response = buffer_str.substring (0, buffer_str.indexOf ("/")); // using delimiter
					
						// computes H’ = Hash (K||M) 
						Hprime = hashing (K + response);
					
						// checks if H = H’
						H = hashing (K + response);
					
						// If the equation holds, then Alice accepts M; otherwise, Alice rejects the ciphertext.
						if (Hprime.equals (H))
						{
							if (response.toLowerCase().contains ("exit"))
							{
								host_socket.close();
								System.out.println ("Client has terminated conversation.\n\tTerminating now...");
								System.exit(1);
							}
							else
							{
								System.out.println ("Bob: " + response);
							}
						}
						else
						{
							host_socket.close();
							System.out.println ("Decryption error!\n");
							System.out.println ("Warning: Incorrect session key!");
							System.out.println ("\tTerminating Session...");
							System.exit(1);
						}
					
						while (host_msg.isEmpty())
						{
							host_msg = session.readInput ("<press enter to send or type exit to close session>\nAlice: ");
						}
						
						Date d = new Date();   // getting system time
						String time = d + " ";  // converting it to String
						host_msg += " | " + d;
						host_msg = host_msg.concat ("/"); // attach delimiter
						// first computes H = Hash(K||M), 
						H = hashing (K + host_msg);
	
						// and then computes C = EK(M||H) and sends C to Bob 
						RC4 rc4e = new RC4 (K.getBytes());
						outgoing_buffer = rc4e.encrypt ((host_msg + H).getBytes());
						outgoing_packet = new DatagramPacket (outgoing_buffer, 0, outgoing_buffer.length, incoming_packet.getAddress(), incoming_packet.getPort());
						host_socket.send (outgoing_packet);
							
						if (host_msg.toLowerCase().contains ("exit")) 
						{
							host_socket.close();
							System.out.println ("User has terminated conversation.\n\tTerminating now...");
							System.exit(1);
						}
						else
						{
							System.out.println ("\nWaiting for incoming message...\n");
						}
					}
				}
				catch (Exception e)
				{
					host_socket.close();
					System.out.println ("Incorrect password! Please try again!");
					System.out.println ("\tTerminating Session...");
					System.exit(1);
				}
			}
			catch (Exception ex) 
			{
				host_socket.close();
				System.out.println ("Exception occured: " + ex.toString());
				ex.printStackTrace();
				System.out.println("\tTerminating Connection...");
				System.exit(1);
			}
		}	
		else
		{
			System.out.println (VAULT + " do not exist.");
			System.out.println ("\tTerminating Window...");
			System.exit (1);
		}
	}
}
