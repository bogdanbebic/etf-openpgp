package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Vector;
import java.util.stream.Collectors;

public class KeyRingTableModel extends DefaultTableModel {
    private static final String [] columnNames = {
            "User ID", "Valid From", "Key ID"
    };

    private static final PublicKeyRingBean dummyKeyRingBean = new PublicKeyRingBean();

    private ArrayList<PublicKeyRingBean> keyRings = new ArrayList<>();

    public Collection<PGPPublicKeyRing> getPublicKeys() {
        return this.keyRings.stream().map(PublicKeyRingBean::getPkr).collect(Collectors.toList());
    }

    public Collection<PGPSecretKeyRing> getPrivateKeys() {
        return this.keyRings.stream().map(e -> ((PrivateKeyRingBean)e).getSkr()).collect(Collectors.toList());
    }

    public void exportRow(int row) {
        Object keyRing = super.getDataVector().get(row);
        if (keyRing instanceof Vector) {
            Vector key = (Vector) keyRing;
            keyRings.stream().filter(element ->
                    element.getValue(0).equals(key.get(0)) &&
                    element.getValue(1).equals(key.get(1)) &&
                    element.getValue(2).equals(key.get(2))
            ).findFirst().ifPresent(PublicKeyRingBean::export);
        }
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return dummyKeyRingBean.getValue(columnIndex).getClass();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return keyRings.get(rowIndex).getValue(columnIndex);
    }

    @Override
    public void removeRow(int row) {
        // delete key
        Object keyRing = super.getDataVector().get(row);
        if (keyRing instanceof Vector) {
            Vector key = (Vector) keyRing;
            keyRings.removeIf(element -> element.getValue(0).equals(key.get(0)) &&
                    element.getValue(1).equals(key.get(1)) &&
                    element.getValue(2).equals(key.get(2)));
        }
        // remove key from UI
        super.removeRow(row);
    }

    public void add(PublicKeyRingBean key) {
        // add key
        keyRings.add(key);
        // add key to UI
        super.addRow(key.toArray());
    }
}
