package etf.openpgp.da160086d;

import java.awt.Color;
import java.awt.Container;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Panel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;

public class GenKeyWindow extends JFrame {
	
	 private JLabel labelName, labelMail, labelSifra, labelRSA1024, labelRSA2048, labelRSA4096;
	 private JTextField tname, tmail, tsifra;
	 private JPanel panel;
	 private Container c;
	 private JButton button;
	 private JRadioButton rsa1024, rsa2048, rsa4096, desEde, aes;
	 private ButtonGroup algorithmSelect;
	 private KeyGeneratorHelper keyGenHelper;
	
	 public GenKeyWindow (String name, KeyGeneratorHelper kgh)
	 {
		super(name);
		keyGenHelper = kgh;
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    
	    setLayout( new GridLayout(7, 2) );
	    
	    labelName = new JLabel ("Ime");
	    labelMail = new JLabel("Mail");
	    labelSifra = new JLabel("Sifra");
	    labelRSA1024 = new JLabel("RSA1024");
	    labelRSA2048 = new JLabel("RSA2048");
	    labelRSA4096 = new JLabel("RSA4096");
	    button = new JButton("Zavrseno");
	    
	    tname = new JTextField(); 
	    tname.setSize(190, 30); 
	    tmail = new JTextField();
	    tmail.setSize(190,30);
	    tsifra = new JTextField();
	    tsifra.setSize(190,30);
	    
	    rsa1024 = new JRadioButton();
	    rsa2048 = new JRadioButton();
	    rsa4096 = new JRadioButton();
	    
	    algorithmSelect = new ButtonGroup();
	    algorithmSelect.add(rsa1024);
	    algorithmSelect.add(rsa2048);
	    algorithmSelect.add(rsa4096);
	    
	    add (labelName);
	    add (tname);
	    add (labelMail);
	    add (tmail);
	    add (labelSifra);
	    add (tsifra);
	    add (labelRSA1024);
	    add (rsa1024);
	    add (labelRSA2048);
	    add (rsa2048);
	    add (labelRSA4096);
	    add (rsa4096);
	    add (button);
	    
	    button.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	int numBits = 0;
            	 if (rsa1024.isSelected())
            		 numBits = 1024;
            	 if (rsa2048.isSelected())
            		 numBits = 2048;
            	 if (rsa4096.isSelected())
            		 numBits = 4096;
				try {
					keyGenHelper.GenerateRSA(tname.getText(), tmail.getText(), tsifra.getText(), numBits);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				} catch (KeyStoreException e1) {
					e1.printStackTrace();
				} catch (CertificateException e1) {
					e1.printStackTrace();
				} catch (PGPException e1) {
					e1.printStackTrace();
				} catch (IOException e1) {
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					e1.printStackTrace();
				}
            }
        });
	 }
}
