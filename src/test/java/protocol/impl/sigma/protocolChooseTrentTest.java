package protocol.impl.sigma;
import static org.junit.Assert.*;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.security.SecureRandom; 

public class protocolChooseTrentTest {

    
	private static int numberUser ;
    private static int numberTrent;
    private static int[] userTrents;
    private static Vector<UserTest> usersContracts;
    private static int State;

    private static void initialize() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        numberUser = 10;
        numberTrent = 5;
        userTrents = new int[numberTrent];
        usersContracts = new Vector<UserTest>();
        // Initialise userContracts.
        for (int i = 0; i < numberUser; i++) 
        {
            UserTest u = new UserTest(i);
            BigInteger randomNumber = new BigInteger(100, new SecureRandom());
            byte[] salt = Hash.generateSalt();
            u.setRandomNumber(randomNumber);
            u.setSalt(salt);
            u.setHashNumber(Hash.calculateHash(randomNumber.toByteArray(), salt));
            usersContracts.add(u);
            State = 0;
        }

        // Initialise table of TTP.
        for (int i = 0; i < numberTrent; i++)
        {
            userTrents[i] = i + 100;
        }
    }

    @Test
    public void protocolFailBecauseCheaterChangeNumber() throws UnsupportedEncodingException, NoSuchAlgorithmException {
		initialize();
        while (State != 3)
        {
            switch (State)
            {
                case 0:// Send public key of the signature.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.addUser(u2.getPublicKey());
                            }
                        }
                    }
                    assertTrue(protocolChooseTrentForTest.verifySendPublicKey(usersContracts));
                    State = 1;

                    break;
                case 1:// Send Hash of number.
                    for (UserTest u1 : usersContracts)
                    {
                        for (UserTest u2 : usersContracts)
                        {
                            if (u1.getPublicKey() != u2.getPublicKey())
                            {
                                u1.receiveHash(u2.getPublicKey(), u2.getHashNumber());
                            }
                        }
                    }
                    assertTrue (protocolChooseTrentForTest.verifySendHash(usersContracts));
                    State = 2;

                    break;
                case 2:// Send salt and randomNumber.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                if (u2.getPublicKey() == 1)
                                    u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSaltFalse(), u2.getRandomNumberFalse());
                                else
                                    u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    assertFalse(protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts));
                    State = 3;

                    break;
            }
        }
        assertTrue(State == 3);
	}

    @Test
    public void protocolFailBecauseCheaterChangeResultTrent() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        initialize();
        while (State != 5)
        {
            switch (State)
            {
                case 0:// Send public key of the signature.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.addUser(u2.getPublicKey());
                            }
                        }
                    }
                    assertTrue (protocolChooseTrentForTest.verifySendPublicKey(usersContracts));
                    State = 1;

                    break;
                case 1:// Send Hash of number.
                    for (UserTest u1 : usersContracts)
                    {
                        for (UserTest u2 : usersContracts)
                        {
                            if (u1.getPublicKey() != u2.getPublicKey())
                            {
                                u1.receiveHash(u2.getPublicKey(), u2.getHashNumber());
                            }
                        }
                    }
                    assertTrue(protocolChooseTrentForTest.verifySendHash(usersContracts));
                    State = 2;

                    break;
                case 2:// Send salt and randomNumber.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    assertTrue(protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts));
                    State = 3;

                    break;
                case 3:// Calc the number to choice the TTP.
                    for (UserTest u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    assertTrue (protocolChooseTrentForTest.verifyAllCalculateResultTrent(usersContracts));
                    State = 4;

                    break;
                case 4:// Send the number of TTP.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                if (u2.getPublicKey() == 1)
                                    u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrentFalse(userTrents));
                                else
                                    u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrent());
                            }
                        }
                    }
                    assertFalse(protocolChooseTrentForTest.verifySendResultTrent(usersContracts));
                    State = 5;
                    break;
            }
        }
    }

	@Test
    public void protocolSuccess() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        initialize();
        while (State != 5)
        {
            switch (State)
             {
                case 0:// Send public key of the signature.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.addUser(u2.getPublicKey());
                            }
                        }
                    }
                    assertTrue (protocolChooseTrentForTest.verifySendPublicKey(usersContracts));
                    State = 1;

				break;
                case 1:// Send Hash of number.
                    for (UserTest u1 : usersContracts)
                    {
                        for (UserTest u2 : usersContracts)
                        {
                            if (u1.getPublicKey() != u2.getPublicKey())
                            {
                                u1.receiveHash(u2.getPublicKey(), u2.getHashNumber());
                            }
                        }
                    }
                    assertTrue(protocolChooseTrentForTest.verifySendHash(usersContracts));
                        State = 2;
				break;
                case 2:// Send salt and randomNumber.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    assertTrue(protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts));
                        State = 3;

				break;
                case 3:// Calc the number to choice the TTP.
                    for (UserTest u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    assertTrue(protocolChooseTrentForTest.verifyAllCalculateResultTrent(usersContracts));
                        State = 4;
				break;
                case 4:// Send the number of TTP.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrent());
                            }
                        }
                    }
                    assertTrue (protocolChooseTrentForTest.verifySendResultTrent(usersContracts));
                    State = 5;
            }
        }
		assertTrue(State == 5);
    }
}
