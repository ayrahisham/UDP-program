// Nur Suhaira Bte Badrul Hisham
// Assignment 1
// 5841549

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SessionWindow 
{

	public static String readInput (String user)
	{
		String line;
		String message = "";
		
		try
		{
			InputStreamReader isr = new InputStreamReader (System.in);
			BufferedReader input = new BufferedReader (isr);
		
			boolean send = false;
			
			while (!send)
			{
				try
				{
					System.out.print (user); // print username
					line = input.readLine();
					
					send = true;
					message = line;
				}
				catch (Exception ex)
				{
					System.out.println ("Invalid input! Try again!");
				}
			}
		}
		catch (Exception e)
		{
			System.err.println ("Error in Console I/O: " + e.getMessage());
		}
		
		return message;
	}
}
