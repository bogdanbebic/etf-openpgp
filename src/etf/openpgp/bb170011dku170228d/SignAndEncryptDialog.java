package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import javax.swing.*;
import java.awt.event.*;

/**
 * Class representing dialog to run on sign/encrypt action
 */
public class SignAndEncryptDialog extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JCheckBox signCheckBox;
    private JCheckBox encryptCheckBox;
    private JTable tableSign;
    private JTable tableEncrypt;
    private JPasswordField passwordField;
    private JCheckBox compressCheckBox;
    private JCheckBox radix64CheckBox;
    private JRadioButton a3DESRadioButton;
    private JRadioButton CAST5RadioButton;
    private final JFileChooser fc = new JFileChooser();

    public SignAndEncryptDialog() {
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onOK();
            }
        });

        buttonCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        });

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    private void onOK() {
        String filename = "";
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            filename = fc.getSelectedFile().getAbsolutePath();
        }

        int rowSign = tableSign.getSelectedRow();
        PGPSecretKeyRing skr = ((KeyRingTableModel)tableSign.getModel()).getSkr(rowSign);

        int rowEncrypt = tableEncrypt.getSelectedRow();
        PGPPublicKeyRing pkr = ((KeyRingTableModel)tableEncrypt.getModel()).getPkr(rowEncrypt);

        try {
            PGPUtility.signEncryptFile(
                    filename,
                    pkr,
                    skr,
                    passwordField.getPassword(),
                    encryptCheckBox.isSelected(),
                    signCheckBox.isSelected(),
                    compressCheckBox.isSelected(),
                    radix64CheckBox.isSelected(),
                    CAST5RadioButton.isSelected());
        } catch (Exception e) {
            e.printStackTrace();
        }


        dispose();
    }

    private void onCancel() {
        // add your code here if necessary
        dispose();
    }

    private void createUIComponents() {
        tableSign = new JTable(Menu.privateKeyRingTableModel);
        tableEncrypt = new JTable(Menu.publicKeyRingTableModel);

        signCheckBox = new JCheckBox(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                passwordField.setEnabled(signCheckBox.isSelected());
            }
        });
        encryptCheckBox = new JCheckBox(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                a3DESRadioButton.setEnabled(encryptCheckBox.isSelected());
                CAST5RadioButton.setEnabled(encryptCheckBox.isSelected());
            }
        });
    }
}
