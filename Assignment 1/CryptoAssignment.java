import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public class CryptoAssignment{

    //Method to convert my byte arrays to hexadecimal
    public static String bytesToHex(byte[] bytesIn) {
            StringBuilder createString = new StringBuilder();
            for(byte b : bytesIn) {
                createString.append(String.format("%02x", b));
            }
            return createString.toString();
    }

    //BigInteger method to encrypt my password with Modular Exponentiation right to left from notes
    public static BigInteger encryptUsingRSA(byte[] pIn, int exp, String mod){
        /*
           y = 1
           for i = 0 to n-1 do
               if xi = 1 then y = (y*a) mod p
               a = (a*a) mod p
           end
        */

        BigInteger n = new BigInteger(mod, 16);
        BigInteger y = new BigInteger("1");
        BigInteger p = new BigInteger(pIn);
        String e = Integer.toBinaryString(exp);

        for(int i = 1; i<= e.length(); i++) {
            if(e.charAt(e.length()-1) == '1') {
                y = y.multiply(p).mod(n);
            }
            p = p.multiply(p).mod(n);
        }
        return y;
    }

    // I was getting UnsupportedEncodingException thats why i throw exception
    public static void main(String [] args) throws Exception{

        //Step 1 : Encode password using UTF-8. Make sure password is strong.

        String password = "One12two"; //Create string password
        byte[] p = password.getBytes("UTF-8"); //Convert password to byte array.
        int numberOfHashes = 200;

        //Step 2 : Randomly generate the salt.

        final Random randomGenerator = new SecureRandom();
        byte[] s = new byte[16];
        randomGenerator.nextBytes(s);
        String saltToHex = bytesToHex(s);
        System.out.println("SALT IN HEX");
        System.out.println(saltToHex);

        //Step 3 : Concatenating password and salt

        //Adding the two byte arrays together
        byte[] ps = new byte[p.length + s.length];
        System.arraycopy(p, 0, ps, 0, p.length);
        System.arraycopy(s, 0, ps, p.length, s.length);

        //Step 4 : Hashing the salt and password 200 times using SHA-256

        // messageDigest package is in the security import.
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        //messageDigest is a cryptographic hash func containing a string of digits concatenated by a one way hashing formula
        byte[] hash = messageDigest.digest(ps); //this is applying the sha hash func to my passwordwithsalt(ps) which is in messageDigest. Calling digest is hashing it?
        //hashing 200 times
        for(int i = 0; i< numberOfHashes; i++)
        {
            hash = messageDigest.digest(hash);
        }

        System.out.println("AES KEY");
        System.out.println(bytesToHex(hash));
        //generating key from hashed password
        //Constructs a secret key from the given byte array - my hashed password).
        SecretKeySpec k = new SecretKeySpec(hash, "AES");

        //Step 5;

        //Reading in a file.
        File file = new File(args[0]); //taken from cmd line
        byte[] fileInBytes = new byte[(int) file.length()]; //making a new byte array the length of the file
        // FileInputStream is meant for reading streams of raw bytes.
        FileInputStream readingBytesFromFile = new FileInputStream(file); //reading in bytes from file
        readingBytesFromFile.read(fileInBytes); //read file bytes into a byte array

        //encrypt this file with k and block of 16
        //initialise cipher - AES CBC mode
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        //generate IV for initilisation
        byte[] iv = new byte[16];
        randomGenerator.nextBytes(iv);
        String ivInHex = bytesToHex(iv);

        System.out.println("IV IN HEX");
        System.out.println(ivInHex);

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        //need to use a random iv each time.
        cipher.init(Cipher.ENCRYPT_MODE, k, ivspec);

        //padding
        int fileLength = (int) file.length();
        int blockSize = 16;

        //padding array
        byte[] pad = new byte[blockSize - (fileLength % 16)];
        //always append 1 then the rest 0's
        pad[0] = (byte) 128;
        for(int i=1; i<pad.length; i++){
            pad[i] = (byte) 0;
        }

        byte[] padAndMsg = new byte[fileLength + pad.length];
        System.arraycopy( fileInBytes, 0, padAndMsg, 0, fileInBytes.length );
        System.arraycopy( pad, 0, padAndMsg, fileInBytes.length, pad.length );

        readingBytesFromFile.close(); //close the stream

        byte [] encryptedMsg = cipher.doFinal(padAndMsg);
        String AESEncryptHex = bytesToHex(encryptedMsg);

        System.out.println("AES encryption in Hex:");
        System.out.println(AESEncryptHex);

        //Step 6:

        //Encrypting password using RSA.
        BigInteger y = new BigInteger("1");
        //public modulus
        String n = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
        int e = 65537; // to string?
        BigInteger passwordEncryptedWithRSA = encryptUsingRSA(padAndMsg, e, n);

        //convert BigInteger to hex
        String passwordEncryptedWithRSAInHex = passwordEncryptedWithRSA.toString(16);
        System.out.println("Password Encrypted using RSA in Hex");
        System.out.println(passwordEncryptedWithRSAInHex);


        FileWriter fw = new FileWriter("answers.txt");
        fw.write("\nAESEncrypted: \n" + AESEncryptHex);
        fw.write("\nPassword encrypted with RSA: \n" + passwordEncryptedWithRSAInHex);
        fw.write("\nSalt: \n"+ saltToHex);
        fw.write("\nIV: \n"+ ivInHex);

        fw.close();

    }
}
