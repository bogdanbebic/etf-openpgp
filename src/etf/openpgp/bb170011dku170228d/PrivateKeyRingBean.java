package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Class encapsulating the PGPSecretKeyRing for use in the UI table
 * and other application actions regarding secret keys
 */
public class PrivateKeyRingBean extends PublicKeyRingBean {
    private final PGPSecretKeyRing skr;

    /**
     * Exports the encapsulated PGPSecretKeyRing to file
     * identified by the user id and key id
     */
    public void export() {
        super.export();
        try (ArmoredOutputStream out = new ArmoredOutputStream(
                new FileOutputStream(super.getUserId() + super.getKeyId() + "-private.asc"))) {
            skr.encode(out);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @return the encapsulated PGPSecretKeyRing
     */
    public PGPSecretKeyRing getSkr() {
        return skr;
    }

    /**
     * Constructs an encapsulating object
     * @param pkr to be encapsulated
     * @param skr to be encapsulated
     */
    public PrivateKeyRingBean(PGPPublicKeyRing pkr, PGPSecretKeyRing skr) {
        super(pkr);
        this.skr = skr;
    }
}
