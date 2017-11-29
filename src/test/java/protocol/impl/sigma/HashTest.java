package protocol.impl.sigma;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import java.security.NoSuchAlgorithmException; 
import java.io.UnsupportedEncodingException; 
import java.security.SecureRandom; 

public class HashTest {

    public static String password1, password2, password2bis;
    public static byte[] salt1, salt2, salt2bis;
    public static byte[] hash1, hash2, hash2bis;

    @BeforeClass
    public static void initialize()
    {
        try
        {
			/* Create 3 password */
			/* password2 identical to password2bis*/
			password1 = "TotallySecurePassword";
			password2 = "TotallySecurePassword12345";
			password2bis = "TotallySecurePassword12345";
			/* Generate 3 salt */
			salt1 = Hash.generateSalt();
			salt2 = Hash.generateSalt();
			salt2bis = Hash.generateSalt();
			/* Calculate 3 hash */
			hash1 = Hash.calculateHash(password1.getBytes("UTF-8"), salt1);
			hash2 = Hash.calculateHash(password2.getBytes("UTF-8"), salt2);
			hash2bis = Hash.calculateHash(password2bis.getBytes("UTF-8"), salt2bis);
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{ 
			fail(ex.getMessage()); 
		}
    }

    @Test
    public void testPassword1(){
        // password1
        try
        {
			/* hash1 identical to hash(salt1 + password1)*/
			assertTrue( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt1) );
			/* hash2 not identical to hash(salt1 + password1) */
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt1) );
			/* hash2bis  not identical to hash(salt1 + password1) */
			assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt1) );
			/* hash1 not identical to hash(salt2 + password1) */
			assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2) );
			/* hash2 not identical to hash(salt2 + password1) */
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2) );
			/* hash2bis not identical to hash(salt2 + password1) */
			assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2) );
			/* hash1 not identical to hash(salt2bis + password1) */
			assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2bis) );
			/* hash2 not identical to hash(salt2bis + password1) */
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2bis) );
			/* hash2bis not identical to hash(salt2bis + password1) */
			assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2bis) );
			
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{ 
			fail(ex.getMessage()); 
		}
	}
	@Test
	public void testPassword2(){
        // password2
        try
        {
			/* hash1 not identical to hash(salt1+ password2) */
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt1) );
			/* hash2 not identical to hash(salt1+ password2) */
			assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt1) );
			/* hash2bis not identical to hash(salt1+ password2) */
			assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt1) );
			/* hash1 not identical to hash(salt+ password2) */
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2) );
			/* hash2 identical to hash(salt2+ password2) */
			assertTrue( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2) ); 
			/* hash2bis not identical to hash(salt2+ password2) */
			assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2) );
			/* hash1 not identical to hash(salt2bis+ password2) */
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2bis) );
			/* hash2 not identical to hash(saltbis+ password2) */
			assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2bis) );
			/* hash2bis identical to hash(salt2bis+ password2) because hash(salt2bis+ password2) <=> hash(salt2bis+ password2bis) (password2 = password2bis)*/
			assertTrue( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2bis) );
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{ 
			fail(ex.getMessage()); 
		}
	}
	@Test
	public void testPassword2bis(){
        // password2bis
        try
        {
			/* hash1 not identical to hash(salt1+ password2bis) */
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt1) );
			/* hash2 not identical to hash(salt1+ password2bis) */
			assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt1) );
			/* hash2bis not identical to hash(salt1+ password2bis) */
			assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt1) );
			/* hash1 not identical to hash(salt2+ password2bis) */
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2) );
			/* hash2 identical to hash(salt2+ password2bis) because hash(salt2+ password2bis) <=> hash(salt2+ password2) (password2 = password2bis)*/
			assertTrue( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2) );
			/* hash2bis not identical to hash(salt2+ password2bis) */
			assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2) );
			/* hash1 not identical to hash(salt2bis+ password2bis) */
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2bis) );
			/* hash2 not identical to hash(salt2bis+ password2bis) */
			assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2bis) );
			/* hash2bis identical to hash(salt2bis+ password2bis) */
			assertTrue( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2bis) );
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{ 
			fail(ex.getMessage()); 
		}
	}
}
