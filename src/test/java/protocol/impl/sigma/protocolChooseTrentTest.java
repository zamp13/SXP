package protocol.impl.sigma;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import java.util.*;
import java.math.BigInteger;
import java.security.SecureRandom; 

public class protocolChooseTrentTest {

    
	private static int numberUser = (int) Math.random()*100;
    private static int numberTrent =  (int) Math.random()*100;
    private static int[] userTrents = new int[numberTrent];
    private static Vector<UserTest> usersContracts = new Vector<UserTest>();
    private static int State;
    private static void initialize()
    {
        numberUser = (int) Math.random()*100;
        numberTrent =  (int) Math.random()*100;
        userTrents = new int[numberTrent];
        // Initialise userContracts.
        for (int i = 0; i < numberUser; i++) 
        {
            User u = new User(i);
            BigInteger randomNumber = new BigInteger(100, new SecureRandom());
            byte[] salt = Hash.generateSalt();
            u.setRandomNumber(randomNumber);
            u.setSalt(salt);
            boolean b = u.setHashNumber(Hash.calculateHash(randomNumber.toByteArray(), salt));
            usersContracts.add(u);
            State = 0;
            // Initialise table of TTP.
			for (int i = 0; i < numberTrent; i++) 
			{
				userTrents[i] = i + 100;
			}
        }
    }    
    @Test
    public static void protocoleFail() 
    {
		initialize();
		assertFalse(False);
	}
    public static void protocoleSuccess()
    {
        while (State != 5)
        {
            switch (State)
             {
                case 0:// Send public key of the signature.
                    for (User u1 : usersContracts) {

                        for (User u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.addUser(u2.getPublicKey());
                            }
                        }
                    }
                    if (protocolChooseTrent.verifySendPublicKey(usersContracts))
                        State = 1;
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 1:// Send Hash of number.
                    for (User u1 : usersContracts) 
                    {
                        for (User u2 : usersContracts) 
                        {
                            if (u1.getPublicKey() != u2.getPublicKey())
                            {
                                u1.receiveHash(u2.getPublicKey(), u2.getHashNumber());
                            }
                        }
                    }
                    if (protocolChooseTrent.verifySendHash(usersContracts))
                    {
                        State = 2;
                    }
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 2:// Send salt and randomNumber.
                    for (User u1 : usersContracts) {

                        for (User u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    if (protocolChooseTrent.verifySendNumberAndSalt(usersContracts))
                        State = 3;
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 3:// Calc the number to choice the TTP.
                    for (User u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    if (protocolChooseTrent.verifyAllCalculateResultTrent(usersContracts))
                        State = 4;
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 4:// Send the number of TTP.
                    for (User u1 : usersContracts) {

                        for (User u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrent());
                            }
                        }
                    }
                    if (protocolChooseTrent.verifySendResultTrent(usersContracts))
                        State = 5;
                    else
					{
                        assertTrue(false);
                        return;
					}
            }
        }
		assertTrue(True);
    }
}
