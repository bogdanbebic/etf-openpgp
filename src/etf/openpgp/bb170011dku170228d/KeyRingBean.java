package etf.openpgp.bb170011dku170228d;

import java.time.Instant;

public class KeyRingBean {
    private String name;
    private String email;
    private Instant validFrom;
    private Instant validTo;
    private char [] keyId;

    public KeyRingBean(String name, String email, Instant validFrom, Instant validTo, char[] keyId) {
        this.name = name;
        this.email = email;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.keyId = keyId;
    }

    public Object[] toArray() {
        return new Object[]{name, email, validFrom, validTo, keyId};
    }

    public Object getValue(int index) {
        switch (index) {
            case 0:
                return name;
            case 1:
                return email;
            case 2:
                return validFrom;
            case 3:
                return validTo;
            case 4:
                return keyId;
            default:
                throw new IndexOutOfBoundsException();
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Instant validFrom) {
        this.validFrom = validFrom;
    }

    public Instant getValidTo() {
        return validTo;
    }

    public void setValidTo(Instant validTo) {
        this.validTo = validTo;
    }

    public char[] getKeyId() {
        return keyId;
    }

    public void setKeyId(char[] keyId) {
        this.keyId = keyId;
    }
}
