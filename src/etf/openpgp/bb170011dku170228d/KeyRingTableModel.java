package etf.openpgp.bb170011dku170228d;

import javax.swing.table.DefaultTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Vector;

public class KeyRingTableModel extends DefaultTableModel {
    private static final String [] columnNames = {
            "Name", "Email", "Valid From", "Valid To", "Key ID"
    };

    private static final KeyRingBean dummyKeyRingBean = new KeyRingBean();

    private ArrayList<KeyRingBean> keyRings = new ArrayList<>();
    {
        KeyRingBean krb = new KeyRingBean("", "", Instant.now(), Instant.now(), new char[]{'a', 'b', 'c', 'd', 'e'});
        super.addRow(krb.toArray());
        keyRings.add(krb);
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
                    element.getValue(2).equals(key.get(2)) &&
                    element.getValue(3).equals(key.get(3)) &&
                    element.getValue(4).equals(key.get(4)));
        }
        // remove key from UI
        super.removeRow(row);
    }

    public void add(KeyRingBean key) {
        // add key
        keyRings.add(key);
        // add key to UI
        super.addRow(key.toArray());
    }
}
