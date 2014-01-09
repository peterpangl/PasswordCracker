/* @author: Peter Panagopoulos */

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordCrackerBF {

    private static String userName;                         // username
    private static String userPassword;                     // password of user that will be converted into hash upon the user enter the password
    private static String salt = "K4D2";                    // predefined value of salt
    
    // creates and returns an MD5 hash code
    public static String getMD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            String hashtext = number.toString(16);                  // convert BigInt to HEX value
            
            while (hashtext.length() < 32) {                        // Need to add zero to get the full 32 chars.
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);		// JVM
        }
    }
    
    public static boolean isValid(String str) {
        int i;
        for (i = 0; i < str.length(); i++) {
            // If we find a non-digit and not Uppercase character, return false.
            if (!Character.isDigit(str.charAt(i)) && !Character.isUpperCase(str.charAt(i)))
                return false;
        }
        return true;
    }
    
    // return true if b is greater than a
    public static boolean checkSpace(String a, String b){
    
        if(a.length() > b.length()){ return false; }
        else if(a.length() < b.length()){ return true; }
        else{                                               // a.length == b.length
            int i;
            for (i = 0; i < a.length(); i++) { 
                // compare two digits 9 is greater than 0
                if (Character.isDigit(a.charAt(i)) && Character.isDigit(b.charAt(i))){
                    if(b.compareTo(a) < 0){ return false; }
                }
                // we consider 9 is greater than A
                if (Character.isDigit(a.charAt(i)) && Character.isLetter(b.charAt(i))){
                    return false;
                }
                // compare two chars
                if (Character.isLetter(a.charAt(i)) && Character.isLetter(b.charAt(i))){
                    if(b.compareTo(a) < 0) { return false; }
                }
            }
            return true;                        // b is greater than a
        }
    }
    
    private char[] charSet;                     // Character Set 
    private char[] currentPass;                 // Current Guess 
    
    // init useful arrays
    public void init(char[] charS, String from) {
        charSet = charS;
        currentPass = from.toCharArray();
    }

    public String toString() { 
        return String.valueOf(currentPass); 
    }
    
    
    public void nextGuess() {
        int index = currentPass.length - 1;        
        while(index >= 0) {
            if (currentPass[index] == charSet[charSet.length-1]) {  // last letter of charSet has been reached
                if (index == 0) {                                   // if we examine the most left element of the tested password
                    currentPass = new char[currentPass.length+1];   // increase the legth of currentPass
                    Arrays.fill(currentPass, charSet[0]);           // init currentPass array
                    break;
                }
                else {                                              // NOT most left element
                    currentPass[index] = charSet[0];
                    index--;                                        // will change the previous symbol of array
                } 
            } 
            else {                                                  // just want to get the next symbol of charSet
                int i;
                for(i = 0; i < charSet.length; i++){                // find current symbol in the charSet
                    if(currentPass[index] == charSet[i]){
                        currentPass[index] = charSet[i+1];
                        break;
                    }
                }
                break; 
            } 
        }
    }
    
    public static void bruteForce(String from, String to, String userHash, String salt) {
        
        char[] characterSet = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}; 
        PasswordCrackerBF bf = new PasswordCrackerBF();
        bf.init(characterSet, from);
        while (true) { 
            String passGuess = bf.toString();
            String passGuessHash = getMD5(passGuess+salt);
            if (passGuessHash.equals(userHash)) {           // password cracked with brute force
                System.out.println("Password's Hash Found: " + passGuessHash + "\n which corresponds to this password: " + passGuess);
                break; 
            }
            if (passGuess.equals(to)) {                     // we reached the limit of searching space without having cracked the password
                System.out.println("upper limit: "+to+" reached!Password not found!Try another space of characters...");
                break;
            }
            System.out.println("Tried: " + passGuess); 
            bf.nextGuess();    
        }
    }

    
    public static void main(String[] args) {
        // take username
		Scanner keyboard = new Scanner(System.in);
		System.out.print("Username: ");
		userName = keyboard.nextLine();
			
        // valid password, only Uppercase Characters and Digits
        while(true){
            System.out.print("Password (Uppercase A-Z & Digits 0-9): ");
            userPassword = keyboard.nextLine();
            if(isValid(userPassword))
                break;
            else
                System.out.println("**Invalid Password, Uppercase Characters and/or Digits only acceptable");
        }

        String userHashValue = getMD5(userPassword+salt);               // userHashValue hex hash value of the password
        System.out.println("your salted hash value: "+ userHashValue);
        
        System.out.println("BruteForce now, testing candidate password's hash values against yours salted hash value\n");
        String from;
        String to;
        while (true){
            System.out.println("Give a string space to search in there for the password");
            System.out.println("For example:from AAAA to A999 or from AA to ABAAA");
            while(true){
                System.out.print("from: ");
                from = keyboard.nextLine();
                if(isValid(from)) { break; }
                else { System.out.println("**Invalid value, use only Uppercase Characters and/or Digits"); }
            }
            while(true){
                System.out.print("to: ");
                to = keyboard.nextLine();
                if(isValid(to)) { break; }
                else { System.out.println("**Invalid value, use only Uppercase Characters and/or Digits"); }
            }
            if(checkSpace(from,to)){ break; }
            else { System.out.println("'from' is greater than 'to'!give desired space again!"); }
        }
        
        //go to crack user's hash value
        bruteForce(from, to, userHashValue, salt);
    }
}

