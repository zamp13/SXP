/**
 * Exemple
public static void main(String[] args)
{ 
	String password = "TotallySecurePassword12345"; 
	String password2 = "TotallySecurePassword"; 
	try 
	{ 
		byte[] salt = Hash.generateSalt(); 
		System.out.print("Salt: " + byteArrayToHexString(salt)+"\n");
		System.out.print("Password bytes: "+ byteArrayToHexString(password.getBytes("UTF-8")) +"\n");
		byte[] hash = Hash.calculateHash(password.getBytes("UTF-8"), salt); 
		System.out.print("Hash: " + byteArrayToHexString(hash)+"\n");
		boolean correct = Hash.verifyPassword(hash, password2.getBytes("UTF-8"), salt); 
		if(correct)
			System.out.print("Identique\n");
		else
			System.out.print("Different\n");
	}
	catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
	{ 
		System.out.print(ex.getMessage()); 
	}
} **/
 
 
import java.io.UnsupportedEncodingException; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.security.SecureRandom; 
public abstract class Hash 
{ 
    private static final String ALGORITHM = "SHA-512"; //Choix de l'algorithme de cryptage
    private static final int ITERATIONS = 1000000;  //Nombre d'itération pour le calcul du hash
    private static final int SALT_SIZE = 64; //Taille du sel
    
	/**
	 * Fonction utilise pour le débug elle convertie un tableau de byte en hexadécimal
	 * @param tableau de bit
	 * @return un string hexadécimal **/
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
	 * Fonction qui génére un sel 
	 * @param aucun 
	 * @return un tableau de byte **/
    public static byte[] generateSalt() 
    { 
        SecureRandom random = new SecureRandom(); 
        byte[] salt = new byte[SALT_SIZE]; 
        random.nextBytes(salt); 
 
        return salt; 
    } 
	
	/**
	 * Fonction qui calcule un hash
	 * @param passwordByte: un tableau de byte qui represente le nombre
	 * @param salt un tableau de byte qui represente le salt
	 * @throws NoSuchAlgorithmException si il ne trouve pas l'algorithme de hashage
	 * @throws UnsupportedEncodingException si il ne supporte pas l'encodage
	 * @return le hash calculé*/
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
     * Fonction qui vérifie un password
     * @param originalHash	 le hash original
     * @param password	 le mots de passe à vérifier
     * @param salt	 le salt
     * @return un booleen qui indique si le mots de passe est identique(true) ou différent(false)*/
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
