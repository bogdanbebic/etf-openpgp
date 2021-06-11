package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

/**
 * Class encapsulating the PGPPublicKeyRing for use in the UI table
 * and other application actions regarding public keys
 */
public class PublicKeyRingBean {
    private String userId = "";
    private Date validFrom = new Date();
    private String keyId = "";

    private PGPPublicKeyRing pkr;

    /**
     *
     * @return the user ID of the encapsulated object
     */
    public String getUserId() {
        return userId;
    }

    /**
     *
     * @return the key ID of the encapsulated object
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     *
     * @return the encapsulated PGPPublicKeyRing
     */
    public PGPPublicKeyRing getPkr() {
        return pkr;
    }

    /**
     * Exports the encapsulated PGPPublicKeyRing to file
     * identified by the user id and key id
     */
    public void export() {
        try (ArmoredOutputStream out = new ArmoredOutputStream(
                new FileOutputStream(userId + keyId + "-public.asc"))) {
            pkr.encode(out);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Default constructor used to make dummy objects
     */
    public PublicKeyRingBean() {}

    /**
     * Constructs an encapsulating object
     * @param pkr to be encapsulated
     */
    public PublicKeyRingBean(PGPPublicKeyRing pkr) {
        this.pkr = pkr;

        this.userId = pkr.getPublicKey().getUserIDs().next();
        this.validFrom = pkr.getPublicKey().getCreationTime();
        this.keyId = Long.toHexString(pkr.getPublicKey().getKeyID());
    }

    /**
     *
     * @return array representation of the current object to be shown in the UI
     */
    public Object[] toArray() {
        return new Object[]{userId, validFrom, keyId};
    }

    /**
     *
     * @param index of the object in the array representation
     * @return object indexed in the array representation
     */
    public Object getValue(int index) {
        switch (index) {
            case 0:
                return userId;
            case 1:
                return validFrom;
            case 2:
                return keyId;
            default:
                throw new IndexOutOfBoundsException();
        }
    }

}
