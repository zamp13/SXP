package protocol.impl.sigma;
import static org.junit.Assert.*;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.math.BigInteger;
import java.security.SecureRandom; 

public class protocolChooseTrentTest {

    
	private static int numberUser = (int) Math.random()*100;
    private static int numberTrent =  (int) Math.random()*100;
    private static int[] userTrents = new int[numberTrent];
    private static Vector<UserTest> usersContracts = new Vector<UserTest>();
    private static int State;

    private static void initialize() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        numberUser = (int) Math.random()*100;
        numberTrent =  (int) Math.random()*100;
        userTrents = new int[numberTrent];
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
                    if (protocolChooseTrentForTest.verifySendPublicKey(usersContracts))
                        State = 1;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
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
                    if (protocolChooseTrentForTest.verifySendHash(usersContracts))
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
                    if (protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts))
                        State = 3;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
                    break;
                case 3:// Calc the number to choice the TTP.
                    for (UserTest u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    if (protocolChooseTrentForTest.verifyAllCalculateResultTrent(usersContracts))
                        State = 4;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
                    break;
                case 4:// Send the number of TTP.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrent());
                            }
                        }
                    }
                    if (protocolChooseTrentForTest.verifySendResultTrent(usersContracts))
                        State = 5;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
            }
        }
		assertTrue(State == 5);
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
                    if (protocolChooseTrentForTest.verifySendPublicKey(usersContracts))
                        State = 1;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
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
                    if (protocolChooseTrentForTest.verifySendHash(usersContracts))
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
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    if (protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts))
                        State = 3;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
                    break;
                case 3:// Calc the number to choice the TTP.
                    for (UserTest u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    if (protocolChooseTrentForTest.verifyAllCalculateResultTrent(usersContracts))
                        State = 4;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
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
                    if (protocolChooseTrentForTest.verifySendResultTrent(usersContracts))
                        State = 5;
                    else
                    {
                        assertTrue(false);
                        return;
                    }
            }
        }
        assertTrue(State == 5);
    }

	@Test
    public void protocolSuccess() throws UnsupportedEncodingException, NoSuchAlgorithmException {
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
                    if (protocolChooseTrentForTest.verifySendPublicKey(usersContracts))
                        State = 1;
                    else
					{
                        assertTrue(false);
                        return;
					}
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
                    if (protocolChooseTrentForTest.verifySendHash(usersContracts))
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
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveNumberAndSalt(u2.getPublicKey(), u2.getSalt(), u2.getRandomNumber());
                            }
                        }
                    }
                    if (protocolChooseTrentForTest.verifySendNumberAndSalt(usersContracts))
                        State = 3;
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 3:// Calc the number to choice the TTP.
                    for (UserTest u1 : usersContracts) {
                        u1.resultTrent(userTrents);
                    }
                    if (protocolChooseTrentForTest.verifyAllCalculateResultTrent(usersContracts))
                        State = 4;
                    else
					{
                        assertTrue(false);
                        return;
					}
				break;
                case 4:// Send the number of TTP.
                    for (UserTest u1 : usersContracts) {

                        for (UserTest u2 : usersContracts) {
                            if (u1.getPublicKey() != u2.getPublicKey()) {
                                u1.receiveResultTrent(u2.getPublicKey(), u2.getResultTrent());
                            }
                        }
                    }
                    if (protocolChooseTrentForTest.verifySendResultTrent(usersContracts))
                        State = 5;
                    else
					{
                        assertTrue(false);
                        return;
					}
            }
        }
		assertTrue(State == 5);
    }
}
