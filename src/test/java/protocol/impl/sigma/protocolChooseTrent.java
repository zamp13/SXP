import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Vector;

import static java.lang.System.exit;

public class protocolChooseTrent {
	
    public static boolean verifySendResultTrent(Vector<UserTest > usersContracts) {

        for(User u1 : usersContracts){
            if ( ! u1.verifyTrent())
                return false;
        }
        return true;
    }

    public static boolean verifyAllCalculateResultTrent(Vector<UserTest > usersContracts) {
        boolean flag = true;

        for(User u1 : usersContracts){
            if( u1.getResultTrent() == -1){
                flag = false;
            }
        }
        return flag;
    }

    public static boolean verifySendNumberAndSalt(Vector<UserTest > usersContracts) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        for (UserTest u : usersContracts) {
            if (! u.verifyHashSaltAndNumber()) {
                System.out.println(! u.verifyHashSaltAndNumber());
                System.out.println( u.getHashNumber() );
                return false;
            }
        }
        return true;
    }

    public static boolean verifySendPublicKey(Vector<UserTest > usersContracts) {
        boolean flag = true;

        for(UserTest u1 : usersContracts){
            for(UserTest u2 : u1.getUsers_contrats()){
                if (u2.getPublicKey() == -1 )
                    flag = false;
            }
        }
        return flag;
    }

    public static boolean verifySendHash(Vector<UserTest > usersContracts) {
        boolean flag = true;

        for(UserTest  u1 : usersContracts){
            for(UserTest  u2 : u1.getUsers_contrats()){
                if (u2.getHashNumber() == null )
                    flag = false;
            }
        }
        return flag;
    }
}
