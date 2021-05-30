package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.FileOutputStream;
import java.io.IOException;

public class PrivateKeyRingBean extends PublicKeyRingBean {
    private PGPSecretKeyRing skr;

    public void export() {
        super.export();
        try (ArmoredOutputStream out = new ArmoredOutputStream(
                new FileOutputStream(userId + keyId + "-private.asc"))) {
            skr.encode(out);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PGPSecretKeyRing getSkr() {
        return skr;
    }

    public PrivateKeyRingBean(PGPPublicKeyRing pkr, PGPSecretKeyRing skr) {
        super(pkr);
        this.skr = skr;
    }
}
