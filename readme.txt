// Nur Suhaira Bte Badrul Hisham
// 5841549
// Assignment 1

Compilation:
============
1. In NurSuhaira_5841549_A1:
	javac *.java 
	// to produce 2 individual vault.txt files for Alice & Bob
	// Unique secret keys are generated 
	// Secret keys are written into the textfiles for reference purposes
	// Each vault.txt file has the following parameters:
		i. password
		ii. value of safe prime
		iii. primitive root for the above safe prime
		iv. Alice's/Bob's secret key
		
2. In NurSuhaira_5841549_A1/Alice:
	javac *.java
	i. execute Host program:
		java Host
	ii. refer to vault.txt for the parameter values
	
3. In NurSuhaira_5841549_A1/Bob:
	javac *.java
	i. execute Client program:
		java Client
	ii. refer to vault.txt for the parameter values

Before Execution:
=================
1. Make sure Host and Client files are compiled with no errors.
2. Make sure that the Host program file is executed
first before execucting on the Client file.

Execute Environment
===================
Operating system: Ubuntu
Using terminal.
