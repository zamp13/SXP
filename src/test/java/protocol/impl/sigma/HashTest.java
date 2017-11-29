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
			password1 = "TotallySecurePassword";
			password2 = "TotallySecurePassword12345";
			password2bis = "TotallySecurePassword12345";
			salt1 = Hash.generateSalt();
			salt2 = Hash.generateSalt();
			salt2bis = Hash.generateSalt();
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
			assertTrue( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2) );
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2) );
			assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2) );
			assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2bis) );
			assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2bis) );
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
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2) );
			assertTrue( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2) ); //true car password2bis = password2
			assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2) );
			assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2bis) );
			assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2bis) );
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
			//password2bis
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt1) );
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2) );
			assertTrue( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2) ); //true car password2bis = password2
			assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2) );
			assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2bis) );
			assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2bis) );
			assertTrue( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2bis) );
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException ex)
		{ 
			fail(ex.getMessage()); 
		}
	}
}
