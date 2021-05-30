package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

import java.util.Date;

public class KeyRingBean {
    private String userId = "";
    private Date validFrom = new Date();
    private String keyId = "";

    private PGPPublicKeyRing pkr;

    public KeyRingBean() {}

    public KeyRingBean(PGPPublicKeyRing pkr) {
        this.pkr = pkr;

        this.userId = pkr.getPublicKey().getUserIDs().next();
        this.validFrom = pkr.getPublicKey().getCreationTime();
        this.keyId = Long.toHexString(pkr.getPublicKey().getKeyID());
    }

    public Object[] toArray() {
        return new Object[]{userId, validFrom, keyId};
    }

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
