package etf.openpgp.bb170011dku170228d;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;

public class Menu {
    private JButton signEncryptButton;
    private JButton decryptVerifyButton;
    private JButton importButton;
    private JButton exportButton;
    private JButton newKeyPairButton;
    private JButton deleteButton;
    private JTabbedPane tabbedPane1;
    private JPanel mainMenu;
    private JPanel privateKeyRingPanel;
    private JPanel publicKeyRingPanel;
    private JTable privateKeysTable;

    static KeyRingTableModel keyRingTableModel = new KeyRingTableModel();

    public static void main(String[] args) {
        JFrame frame = new JFrame("Menu");
        frame.setContentPane(new Menu().mainMenu);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainMenu = new JPanel();
        mainMenu.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        mainMenu.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        signEncryptButton = new JButton();
        signEncryptButton.setText("Sign/Encrypt...");
        panel1.add(signEncryptButton);
        decryptVerifyButton = new JButton();
        decryptVerifyButton.setText("Decrypt/Verify");
        panel1.add(decryptVerifyButton);
        importButton = new JButton();
        importButton.setText("Import...");
        panel1.add(importButton);
        exportButton = new JButton();
        exportButton.setEnabled(false);
        exportButton.setText("Export...");
        panel1.add(exportButton);
        newKeyPairButton = new JButton();
        newKeyPairButton.setText("New Key Pair");
        panel1.add(newKeyPairButton);
        deleteButton = new JButton();
        deleteButton.setEnabled(false);
        deleteButton.setText("Delete");
        panel1.add(deleteButton);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainMenu.add(panel2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        tabbedPane1 = new JTabbedPane();
        panel2.add(tabbedPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("PrivateKeyRing", panel3);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("PublicKeyRing", panel4);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainMenu;
    }

    {
        // action listeners
        signEncryptButton.addActionListener((e -> {
            // TODO: implement
        }));
        decryptVerifyButton.addActionListener((e -> {
            // TODO: implement
        }));
        importButton.addActionListener((e -> {
            // TODO: implement
        }));
        exportButton.addActionListener((e -> {
            // TODO: implement
        }));
        newKeyPairButton.addActionListener((e -> {
            KeyCreationDialog dialog = new KeyCreationDialog();
            dialog.pack();
            dialog.setVisible(true);
        }));
        deleteButton.setEnabled(true); // TODO: maybe delete later
        deleteButton.addActionListener((e -> {
            JTable selectedTable = privateKeysTable;
            int rowToRemove = selectedTable.getSelectedRow();
            if (rowToRemove != -1)
                ((DefaultTableModel)selectedTable.getModel()).removeRow(rowToRemove);
            // deleteButton.setEnabled(false);
        }));
    }

    {
        // load public and private key rings
        File publicRingFile = new File("dummy.pkr");
        File privateRingFile = new File("dummy.skr");
        // TODO: implement
    }

    private void createUIComponents() {
        privateKeysTable = new JTable(keyRingTableModel);
    }
}
