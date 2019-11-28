// Nur Suhaira Bte Badrul Hisham
// Assignment 1
// 5841549

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Date;

import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.NoSuchElementException;
import java.io.IOException;

import java.math.BigInteger;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

public class Client
{

	private static final int BYTESIZE = 4096;
	private static final int PORTNUMBER = 49445;
	private static final String VAULT = "vault.txt";

	private static DatagramSocket client_socket;
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
		for (BigInteger x = BigInteger.ONE; x.compareTo (bigP) < 0 ; x = x.add (BigInteger.ONE))
		{
			if (bigG.modPow (x, bigP).equals (bigH))
			{
				return x;
			}
		}
		
		return BigInteger.ZERO;
	}
	
	public static String computeSessionKey (BigInteger h, BigInteger y, BigInteger p)
	{
		BigInteger sum = h.modPow (y, p);
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
		BigInteger bigY = BigInteger.ZERO;
		BigInteger cclientSK; // computation of g^x mod p
		String hostSK = "";
		byte buffer [] = new byte [BYTESIZE];
		
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
					bigY = file.nextBigInteger ();
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
				System.out.println ("Requesting connection to Host...");
				
				String request_msg = "Hi I'm Bob, I'm requesting for connection.";
			
				client_socket = new DatagramSocket ();
				incoming_packet = new DatagramPacket (new byte[BYTESIZE], BYTESIZE);
				InetAddress ip_address = InetAddress.getByName ("localhost");

				// Client sends a connection request to host
				outgoing_buffer = request_msg.getBytes();
				outgoing_packet = new DatagramPacket (outgoing_buffer, 0, outgoing_buffer.length, ip_address, PORTNUMBER);
				client_socket.send (outgoing_packet);
				
				// Client listens to port to receive packet from host
				System.out.println ("Listening to port for Host...\n");
				
				client_socket.receive (incoming_packet);
				System.out.println ("Receiving packet from Host...\n");
				
				System.out.println ("Preparing packet for Host...");
		    		// computes g^x mod p, encrypts it using RC4, and sends the ciphertext to Host (using SK)
				cclientSK = bigG.modPow (bigY, bigP); 
				String cclientSK_str = cclientSK.toString ();
				
				// encrypt using rc4
				RC4 rc4E = new RC4 (password.getBytes ());
				buffer = rc4E.encrypt (cclientSK_str.getBytes ());
				outgoing_packet = new DatagramPacket (buffer, 0, buffer.length, ip_address, PORTNUMBER);
				client_socket.send (outgoing_packet);
				System.out.println ("Sending packet to Host...\n");
				
				try
				{
					// decrypting host's secret key from packet
					System.out.println ("Decrypting packet...");
					incoming_buffer = incoming_packet.getData ();
				
					// create rc4 with password
					RC4 rc4D = new RC4 (password.getBytes());
					buffer = rc4D.decrypt (incoming_buffer);
					String buffer_str = new String (buffer, 0, incoming_packet.getLength ());
					BigInteger h = new BigInteger (buffer_str);
				
					/*
					// Find the unique number x<p such that h = g^x mod p
					BigInteger x = discreteLogarithm (h, bigG, bigP);
					*/
				
					// make sure x is not 0
					// compute session key
					// g^x mod p = h^y mod p = g^(xy) mod p	
					String K = computeSessionKey (h, bigY, bigP);
					System.out.println ("Session key: " + K);
					System.out.println ("Session key generated successfully...\n");
				
					System.out.println ("Waiting for Host's confirmation...\n");
				
					// check if connection is established from host's confirmation
					client_socket.receive (incoming_packet);
					incoming_buffer = incoming_packet.getData();
					RC4 rc4D2 = new RC4 (password.getBytes ());				
					String confirmation = new String (rc4D2.decrypt(incoming_buffer), 0, incoming_packet.getLength());
					if (confirmation.equalsIgnoreCase ("established")) 
					{
						System.out.println (confirmation + " connection with Alice..." + "\n");
					
					
						String client_msg;
						String H = "";
						String Hprime = "";
						SessionWindow session = new SessionWindow ();
						String response = "";
					
						while (true)
						{	
							client_msg = "";
							while (client_msg.isEmpty())
							{
								client_msg = session.readInput ("<press enter to send or type exit to close session>\nBob: ");
							}
						
							Date d = new Date();   // getting system time
							String time = d + " ";  // converting it to String
							client_msg += " | " + d;
							client_msg = client_msg.concat ("/"); // attach delimiter
							// first computes H = Hash(K||M), 
							H = hashing (K + client_msg);
	
							// and then computes C = EK(M||H) and sends C to Alice 
							RC4 rc4e = new RC4 (K.getBytes());
							outgoing_buffer = rc4e.encrypt ((client_msg + H).getBytes());
							outgoing_packet = new DatagramPacket (outgoing_buffer, 0, outgoing_buffer.length, ip_address, PORTNUMBER);
							client_socket.send (outgoing_packet);
							
							if (client_msg.toLowerCase().contains ("exit")) 
							{
								client_socket.close();
								System.out.println ("User has terminated conversation.\n\tTerminating now...");
								System.exit(1);
							}
							else
							{
								System.out.println ("\nWaiting for incoming message...\n");
							}
						
							client_socket.receive (incoming_packet);
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
					
							// If the equation holds, then Bob accepts M; otherwise, Bob rejects the ciphertext.
							if (Hprime.equals (H))
							{
								if (response.toLowerCase().contains ("exit"))
								{
									client_socket.close();
									System.out.println ("Host has terminated conversation.\n\tTerminating now...");
									System.exit(1);
								}
								else
								{
									System.out.println ("Alice: " + response);
								}
							}
							else
							{
								client_socket.close();
								System.out.println ("Decryption error!\n");
								System.out.println ("Warning: Incorrect session key!");
								System.out.println ("\tTerminating Session...");
								System.exit(1);
							}
						}
					}
					else
					{
						client_socket.close();
						System.out.println ("Host rejects session.");
						System.out.println ("\tTerminating Session...");
						System.exit(1);
					}
				
				}
				catch (Exception e)
				{
					client_socket.close();
					System.out.println ("Incorrect password! Please try again!");
					System.out.println ("\tTerminating Session...");
					System.exit(1);
				}
			}
			catch (Exception ex) 
			{
				client_socket.close();
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
