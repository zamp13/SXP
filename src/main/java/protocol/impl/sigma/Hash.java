/**
 *	Class for hashing a password
} **/
 
package protocol.impl.sigma;
import java.io.UnsupportedEncodingException; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.security.SecureRandom; 
public abstract class Hash 
{ 
    private static final String ALGORITHM = "SHA-512"; //Choosing the encryption algorithm
    private static final int ITERATIONS = 100000;  //Iteration number for hash calculation
    private static final int SALT_SIZE = 64; //Size of salt
    
	/**
	 * Function uses for debug, it converts a byte array to hexadecimal
	 * @param	byte array to convert
	 * @return 	 hexadecimal string **/
    public static String byteArrayToHexString(byte[] bArray)
	{
		StringBuffer buffer = new StringBuffer();
 
		for(byte b : bArray) 
		{
			buffer.append(Integer.toHexString(0xFF & b));
		}
		return buffer.toString().toUpperCase();
    }
	/**
	 * Function which generates the salt
	 * @param	
	 * @return  random salt **/
    public static byte[] generateSalt() 
    { 
        SecureRandom random = new SecureRandom(); 
        byte[] salt = new byte[SALT_SIZE]; 
        random.nextBytes(salt); 
 
        return salt; 
    } 
	
	/**
	 * Fonction which calculates the hash
	 * @param passwordByte it takes the Password
	 * @param salt	it takes the salt
	 * @throws NoSuchAlgorithmException  if it didn't find the algorithme of hash 
	 * 	 * @throws UnsupportedEncodingException if it didn't support encoding
	 * @return A hash */
    public static byte[] calculateHash(byte[] passwordByte, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException 
    { 
        byte[] concat = new byte[salt.length + passwordByte.length];
		System.arraycopy(salt, 0, concat, 0, salt.length);
		System.arraycopy(passwordByte, 0, concat, salt.length, passwordByte.length);
        MessageDigest md = MessageDigest.getInstance(ALGORITHM); 
        md.reset(); 
        md.update(concat);
        byte[] hash = md.digest(); 
        for (int i = 0; i < ITERATIONS; i++)
        { 
            md.reset(); 
            hash = md.digest(hash); 
        } 
 
        return hash; 
    } 
    
    /**
     * Compare pasword and password+salt 
     * @param originalHash	 Orignal hash
     * @param password	 The comparison password hash
     * @param salt	The comparison password salt
     * @return True if both match, false otherwise */
    public static boolean verifyPassword(byte[] originalHash, byte[] password, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException
    { 
        byte[] comparisonHash = calculateHash(password, salt); 
        return comparePasswords(originalHash, comparisonHash); 
    }
 
    /**
     * Compares the two byte arrays in length-constant time using XOR. 
     * 
     * @param originalHash   The original password hash 
     * @param comparisonHash The comparison password hash 
     * @return True if both match, false otherwise 
     */ 
    private static boolean comparePasswords(byte[] originalHash, byte[] comparisonHash) 
    { 
        int diff = originalHash.length ^ comparisonHash.length; 
        for (int i = 0; i < originalHash.length && i < comparisonHash.length; i++)
        { 
            diff |= originalHash[i] ^ comparisonHash[i]; 
        } 
        return diff == 0; 
    }    
}
