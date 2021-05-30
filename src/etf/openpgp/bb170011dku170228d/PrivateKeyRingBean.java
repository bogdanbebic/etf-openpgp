package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class PrivateKeyRingBean extends PublicKeyRingBean {
    private PGPSecretKeyRing skr;

    public PGPSecretKeyRing getSkr() {
        return skr;
    }

    public PrivateKeyRingBean(PGPPublicKeyRing pkr, PGPSecretKeyRing skr) {
        super(pkr);
        this.skr = skr;
    }
}
