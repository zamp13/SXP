package protocol.impl.sigma;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import protocol.impl.sigma.steps.SHA512

public class SHA512Test {

    public String password1, password2, password2bis;
    public byte[] salt1, salt2, salt2bis;
    public byte[] hash1, hash2, hash2bis;

    @BeforeClass
    public static void initialize(){
        password1 = "TotallySecurePassword";
        password2 = "TotallySecurePassword12345";
        password2bis = "TotallySecurePassword12345";
        salt1 = SHA512.generateSalt();
        salt2 = SHA512.generateSalt();
        salt2bis = SHA512.generateSalt();
        hash1 = SHA512.calculateHash(password.getBytes("UTF-8"), salt1);
        hash2 = SHA512.calculateHash(password2.getBytes("UTF-8"), salt2);
        hash2bis = SHA512.calculateHash(password2bis.getBytes("UTF-8"), salt2bis);
    }

    @Test
    public void hashage(){
        // password1
        assertTrue( SHA512.verifyPassword(hash1, password1.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2, password1.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash1, password1.getBytes("UTF-8"), salt2bis) );
        assertFalse( SHA512.verifyPassword(hash2, password1.getBytes("UTF-8"), salt2bis) );
        assertFalse( SHA512.verifyPassword(hash2bis, password1.getBytes("UTF-8"), salt2bis) );
        //password2
        assertTrue( SHA512.verifyPassword(hash1, password2.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2, password2.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2) );
        assertTrue( SHA512.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash1, password2.getBytes("UTF-8"), salt2bis) );
        assertFalse( SHA512.verifyPassword(hash2, password2.getBytes("UTF-8"), salt2bis) );
        assertFalse( SHA512.verifyPassword(hash2bis, password2.getBytes("UTF-8"), salt2bis) );
        //password2bis
        assertTrue( SHA512.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt1) );
        assertFalse( SHA512.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2) );
        assertFalse( SHA512.verifyPassword(hash1, password2bis.getBytes("UTF-8"), salt2bis) );
        assertFalse( SHA512.verifyPassword(hash2, password2bis.getBytes("UTF-8"), salt2bis) );
        assertTrue( SHA512.verifyPassword(hash2bis, password2bis.getBytes("UTF-8"), salt2bis) );
    }


}