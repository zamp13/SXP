package protocol.impl.sigma;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class HashTest {

    public String password1, password2, password2bis;
    public byte[] salt1, salt2, salt2bis;
    public byte[] hash1, hash2, hash2bis;

    @BeforeClass
    public static void initialize(){
        password1 = "TotallySecurePassword";
        password2 = "TotallySecurePassword12345";
        password2bis = "TotallySecurePassword12345";
        salt1 = Hash.generateSalt();
        salt2 = Hash.generateSalt();
        salt2bis = Hash.generateSalt();
        hash1 = Hash.calculateHash(password.getBytes("UTF-8"), salt1);
        hash2 = Hash.calculateHash(password2.getBytes("UTF-8"), salt2);
        hash2bis = Hash.calculateHash(password2bis.getBytes("UTF-8"), salt2bis);
    }

    @Test
    public void hashage(){
        // password1
        assertTrue( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2bis) );
        assertFalse( Hash.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2bis) );
        assertFalse( Hash.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2bis) );
        //password2
        assertTrue( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2) );
        assertTrue( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2bis) );
        assertFalse( Hash.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2bis) );
        assertFalse( Hash.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2bis) );
        //password2bis
        assertTrue( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( Hash.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2bis) );
        assertFalse( Hash.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2bis) );
        assertTrue( Hash.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2bis) );
    }


}
