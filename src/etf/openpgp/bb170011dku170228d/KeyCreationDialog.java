package etf.openpgp.bb170011dku170228d;

import javax.swing.*;
import java.awt.event.*;

public class KeyCreationDialog extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JTextField txtName;
    private JTextField txtEmail;
    private JPasswordField txtPassword;
    private JRadioButton radioRsa1024;
    private JRadioButton radioRsa2048;
    private JRadioButton radioRsa4096;

    public KeyCreationDialog() {
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
        // add your code here
        int keySize = 1024;
        if (radioRsa2048.isSelected())
            keySize = 2048;
        else if (radioRsa4096.isSelected())
            keySize = 4096;
        String id = txtName.getText() + ";" + txtEmail.getText();
        RsaGeneration.generateKey(keySize, id, txtPassword.getPassword());
        dispose();
    }

    private void onCancel() {
        // add your code here if necessary
        dispose();
    }

}
