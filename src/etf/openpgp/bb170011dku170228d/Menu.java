package etf.openpgp.bb170011dku170228d;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;

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
    private JTable publicKeysTable;

    static KeyRingTableModel privateKeyRingTableModel = new KeyRingTableModel();
    static KeyRingTableModel publicKeyRingTableModel = new KeyRingTableModel();

    public static void main(String[] args) {
        JFrame frame = new JFrame("Menu");
        frame.setContentPane(new Menu().mainMenu);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                super.windowClosing(e);

                try {
                    // private keys
                    PGPPublicKeyRingCollection keyRingCollectionPublic =
                            new PGPPublicKeyRingCollection(privateKeyRingTableModel.getPublicKeys());
                    PGPSecretKeyRingCollection keyRingCollectionPrivate =
                            new PGPSecretKeyRingCollection(privateKeyRingTableModel.getPrivateKeys());

                    BufferedOutputStream publicKeysOut =
                            new BufferedOutputStream(new FileOutputStream("keys.pkr"));
                    keyRingCollectionPublic.encode(publicKeysOut);
                    publicKeysOut.close();

                    BufferedOutputStream privateKeysOut =
                            new BufferedOutputStream(new FileOutputStream("keys.skr"));
                    keyRingCollectionPrivate.encode(privateKeysOut);
                    privateKeysOut.close();

                    // unpaired public keys
                    PGPPublicKeyRingCollection keyRingCollectionUnpaired =
                            new PGPPublicKeyRingCollection(publicKeyRingTableModel.getPublicKeys());

                    BufferedOutputStream unpairedKeysOut =
                            new BufferedOutputStream(new FileOutputStream("unpaired.pkr"));
                    keyRingCollectionUnpaired.encode(unpairedKeysOut);
                    unpairedKeysOut.close();

                } catch (IOException | PGPException ioException) {
                    ioException.printStackTrace();
                }

                frame.dispose();
            }
        });
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
            SignAndEncryptDialog dialog = new SignAndEncryptDialog();
            dialog.pack();
            dialog.setVisible(true);
        }));
        decryptVerifyButton.addActionListener((e -> {
            DecryptAndVerifyDialog dialog = new DecryptAndVerifyDialog();
            dialog.pack();
            dialog.setVisible(true);
        }));
        importButton.addActionListener((e -> {
            try {
                JFileChooser fc = new JFileChooser();
                fc.setFileFilter(new FileNameExtensionFilter("ASC files", "asc"));
                if (fc.showOpenDialog(mainMenu) == JFileChooser.APPROVE_OPTION) {
                    PGPPublicKeyRing pkr = new PGPPublicKeyRing(
                            PGPUtil.getDecoderStream(new FileInputStream(fc.getSelectedFile().getAbsolutePath())),
                            new BcKeyFingerprintCalculator());
                    publicKeyRingTableModel.add(new PublicKeyRingBean(pkr));
                }
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }));
        exportButton.setEnabled(true); // TODO: maybe delete later
        exportButton.addActionListener((e -> {
            JTable selectedTable = privateKeysTable;
            if (tabbedPane1.getSelectedIndex() == 1)
                selectedTable = publicKeysTable;
            int rowToExport = selectedTable.getSelectedRow();
            if (rowToExport != -1)
                ((KeyRingTableModel)selectedTable.getModel()).exportRow(rowToExport);
            // exportButton.setEnabled(false);
        }));
        newKeyPairButton.addActionListener((e -> {
            KeyCreationDialog dialog = new KeyCreationDialog();
            dialog.pack();
            dialog.setVisible(true);
        }));
        deleteButton.setEnabled(true); // TODO: maybe delete later
        deleteButton.addActionListener((e -> {
            JTable selectedTable = privateKeysTable;
            if (tabbedPane1.getSelectedIndex() == 1)
                selectedTable = publicKeysTable;
            int rowToRemove = selectedTable.getSelectedRow();
            if (rowToRemove != -1) {
                if (selectedTable.equals(privateKeysTable)) {
                    KeyDeletionDialog dialog = new KeyDeletionDialog();
                    dialog.pack();
                    dialog.setVisible(true);
                    PBESecretKeyDecryptor dec = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(dialog.getPassphrase());
                    PGPSecretKeyRing skr = ((KeyRingTableModel)selectedTable.getModel()).getSkr(rowToRemove);
                    try {
                        if (skr.getSecretKey().extractPrivateKey(dec) == null) {
                            return;
                        }
                    } catch (PGPException pgpException) {
                        return;
                    }
                }
                ((DefaultTableModel)selectedTable.getModel()).removeRow(rowToRemove);
            }
            // deleteButton.setEnabled(false);
        }));
    }

    static {
        try {
            PGPSecretKeyRingCollection skrCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream("keys.skr")),
                    new BcKeyFingerprintCalculator()
            );
            PGPPublicKeyRingCollection pkrCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream("keys.pkr")),
                    new BcKeyFingerprintCalculator()
            );
            Iterator<PGPPublicKeyRing> itPkr = pkrCollection.getKeyRings();
            Iterator<PGPSecretKeyRing> itSkr = skrCollection.getKeyRings();
            while (itPkr.hasNext() && itSkr.hasNext()) {
                PGPPublicKeyRing nextPkr = itPkr.next();
                PGPSecretKeyRing nextSkr = itSkr.next();
                privateKeyRingTableModel.add(new PrivateKeyRingBean(nextPkr, nextSkr));
            }

            PGPPublicKeyRingCollection unpairedCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream("unpaired.pkr")),
                    new BcKeyFingerprintCalculator()
            );
            unpairedCollection.forEach(unpairedKey -> publicKeyRingTableModel.add(new PublicKeyRingBean(unpairedKey)));

        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    private void createUIComponents() {
        privateKeysTable = new JTable(privateKeyRingTableModel);
        publicKeysTable = new JTable(publicKeyRingTableModel);
    }
}
