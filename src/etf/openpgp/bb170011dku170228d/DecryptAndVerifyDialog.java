package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.openpgp.PGPException;

import javax.swing.*;
import java.awt.event.*;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Optional;

/**
 * Class representing dialog to run on decrypt/verify action
 */
public class DecryptAndVerifyDialog extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JPasswordField passwordField;
    private JTable table;
    private final JFileChooser fc = new JFileChooser();

    public DecryptAndVerifyDialog() {
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

        try {
            Optional<String> message = PGPUtility.decryptAndVerify(
                filename,
                passwordField.getPassword());
            message.ifPresent(s -> JOptionPane.showMessageDialog(this, s));
        } catch (IOException | PGPException | SignatureException e) {
            e.printStackTrace();
        }

        dispose();
    }

    private void onCancel() {
        // add your code here if necessary
        dispose();
    }

    private void createUIComponents() {
        table = new JTable(Menu.privateKeyRingTableModel);
    }
}
