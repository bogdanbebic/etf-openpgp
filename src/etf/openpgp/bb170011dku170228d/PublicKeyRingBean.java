package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

public class PublicKeyRingBean {
    protected String userId = "";
    private Date validFrom = new Date();
    protected String keyId = "";

    private PGPPublicKeyRing pkr;

    public PGPPublicKeyRing getPkr() {
        return pkr;
    }

    public void export() {
        try (ArmoredOutputStream out = new ArmoredOutputStream(
                new FileOutputStream(userId + keyId + "-public.asc"))) {
            pkr.encode(out);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PublicKeyRingBean() {}

    public PublicKeyRingBean(PGPPublicKeyRing pkr) {
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
