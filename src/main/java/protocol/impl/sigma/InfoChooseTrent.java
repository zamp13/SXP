package protocol.impl.sigma;

import java.math.BigInteger;

/**
 * Class InfoChooseTrent: Permet de stocker les données d'un utilisateur lors du protocles de choix du TTP
 */
public class InfoChooseTrent {
    private String publicKey;
    private byte[] hashNumber;
    private byte[] salt;
    private BigInteger randomNumber;


    public InfoChooseTrent(String publicKey){
        this.publicKey = publicKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getHashNumber() {
        return hashNumber;
    }

    public void setHashNumber(byte[] hashNumber) {
        this.hashNumber = hashNumber;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public BigInteger getRandomNumber() {
        return randomNumber;
    }

    public void setRandomNumber(BigInteger randomNumber) {
        this.randomNumber = randomNumber;
    }



}
