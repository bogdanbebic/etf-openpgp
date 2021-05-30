package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class SecretKeyRingBean extends KeyRingBean {
    private PGPSecretKeyRing skr;

    public SecretKeyRingBean(PGPPublicKeyRing pkr, PGPSecretKeyRing skr) {
        super(pkr);
        this.skr = skr;
    }
}
