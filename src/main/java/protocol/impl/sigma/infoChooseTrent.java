package protocol.impl.sigma;

import java.math.BigInteger;

public class infoChooseTrent {
    private String publicKey;
    private byte[] hashNumber;
    private byte[] salt;
    private BigInteger randomNumber;


    public infoChooseTrent(String publicKey){
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
