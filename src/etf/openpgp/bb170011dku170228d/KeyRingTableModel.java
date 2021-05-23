package etf.openpgp.bb170011dku170228d;

import javax.swing.table.DefaultTableModel;
import java.time.Instant;
import java.util.ArrayList;

public class KeyRingTableModel extends DefaultTableModel {
    private static final String [] columnNames = {
            "Name", "Email", "Valid From", "Valid To", "Key ID"
    };

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
        return keyRings.get(0).getValue(columnIndex).getClass();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return keyRings.get(rowIndex).getValue(columnIndex);
    }

    @Override
    public void removeRow(int row) {
        super.removeRow(row);
    }
}
