/*
 Class représentant un utilisateur de SXP.
 Utilisateur spécifique pour l'implémentation du protocol du choix de TTP.
*/

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Vector;

public class UserTest {
    private int publicKey;
    private BigInteger randomNumber;
    private byte[] salt;
    private byte[] hashNumber;
    private int resultTrent;
    private Vector<UserTest> users_contrats;

    public UserTest(int publicKey){
        this.publicKey = publicKey;
        this.randomNumber = null;
        this.salt = null;
        this.hashNumber = null;
        this.users_contrats = new Vector<User>();
        this.resultTrent = -1;
    }

    public int getPublicKey() {
        return publicKey;
    }

    public BigInteger getRandomNumber() {
        return randomNumber;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getHashNumber() {
        return hashNumber;
    }

    public Vector<UserTest> getUsers_contrats() {
        return users_contrats;
    }

    public int getResultTrent() {
        return resultTrent;
    }

    public void addUser(int publicKey){
        this.users_contrats.add(new User(publicKey));
    }

    public void setRandomNumber(BigInteger randomNumber) {
        if (this.randomNumber == null)
            this.randomNumber = randomNumber;
    }

    public void setSalt(byte[] salt) {
        if(this.salt == null)
            this.salt = salt;
    }

    public void setHashNumber(byte[] hashNumber) {
         if (this.hashNumber == null ) 
         {
             this.hashNumber = hashNumber;
         }
    }

    public void setResultTrent(int resultTrent) 
    {
        if (this.resultTrent == -1 || this.resultTrent == resultTrent){
            this.resultTrent = resultTrent;
        }
    }

    /**
     * Verify and initialise the Hash received.
     * @param publicKey
     * @param hashNumber
     * @return cheat
     */
    public void receiveHash(int publicKey, byte [] hashNumber){
        for (User u : this.users_contrats) {
            if (u.getPublicKey() == publicKey){
                if (u.getHashNumber() == null){
                    u.setHashNumber(hashNumber);
                }
            }
        }
    }

    /**
     * Verify and initialise the Number and the Salt received.
     * @param publicKey
     * @param salt
     * @param randomNumber
     */
    public void receiveNumberAndSalt(int publicKey, byte [] salt, BigInteger randomNumber){

        for (User u : this.users_contrats) {
            if (u.getPublicKey() == publicKey){
                u.setSalt(salt);
                u.setRandomNumber(randomNumber);
            }
        }
    }


    /**
     * Calc the public key of TTP.
     * @param usersTrent
     */
    public void resultTrent(int[] usersTrent){
        BigInteger publicKeyTrent = new BigInteger("0");
        publicKeyTrent.add(this.randomNumber);

        for (User u : this.users_contrats)
            publicKeyTrent.add(u.getRandomNumber());

        publicKeyTrent = (publicKeyTrent.mod(BigInteger.valueOf(usersTrent.length)));
        this.resultTrent =  usersTrent[publicKeyTrent.intValue()];
    }

    /**
     * Verify and initialise the result of trent received.
     * @param publicKey
     * @param resultTrent
     */
    public void receiveResultTrent(int publicKey, int resultTrent){
        for (User u : this.users_contrats)
            if (u.getPublicKey() == publicKey)
                 u.setResultTrent(resultTrent);

    }

    public boolean verifyHashSaltAndNumber() throws UnsupportedEncodingException, NoSuchAlgorithmException {

        for(User u2 : this.getUsers_contrats())
                if( ! Hash.verifyPassword(u2.getHashNumber(), u2.getRandomNumber().toByteArray(),u2.getSalt()) )
                    return false;
        return true;
    }

    @Override
    public String toString() {
        return "User{" +
                "publicKey=" + publicKey +
                ", randomNumber=" + randomNumber +
                ", salt=" + Arrays.toString(salt) +
                ", hashNumber=" + Arrays.toString(hashNumber) +
                ", resultTrent=" + resultTrent +
                ", users_contrats=" + users_contrats +
                '}';
    }

    public boolean verifyTrent() {
        for(User u2 : this.getUsers_contrats()){
            if (u2.getResultTrent() != this.getResultTrent())
                return false;
        }
        return true;
    }
}
