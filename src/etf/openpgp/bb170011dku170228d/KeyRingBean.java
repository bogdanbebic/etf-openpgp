package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.Serializable;
import java.util.Date;

public class KeyRingBean implements Serializable {
    private String userId = "";
    private Date validFrom = new Date();
    private String keyId = "";

    private PGPPublicKeyRing pkr;
    private PGPSecretKeyRing skr;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public KeyRingBean() {}

    public KeyRingBean(PGPPublicKeyRing pkr, PGPSecretKeyRing skr) {
        this.pkr = pkr;
        this.skr = skr;

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
