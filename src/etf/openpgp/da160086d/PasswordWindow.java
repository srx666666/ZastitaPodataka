package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PasswordWindow extends JFrame{

	private JLabel labelPass;
	private JTextField fieldPass;
	private JButton btn;
	private PGPSecretKeyRing secretKeyRing;
	private boolean delete;
	private PGPPrivateKey privateKey = null;
	
	public PasswordWindow(String name, long id, KeyGeneratorHelper kgh, boolean del, MessageSender msgSender) {
		super(name);
		this.delete = del;
		secretKeyRing = kgh.GetPrivateKeyById(id);
		if (secretKeyRing == null)
		{
			kgh.writeMessage("Pogresan id kljuca kome se trazi sifra.");
			dispose();
			return;
		}
		setSize( 500, 300 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    
	    setLayout( new GridLayout(4, 1) );
	    
	    JLabel labelId = new JLabel("Id kljuca: "+Long.toString(id));
	    labelPass = new JLabel("Unesite lozinku: ");
	    fieldPass = new JTextField();
	    fieldPass.setSize(190,30);   
	    btn = new JButton("OK");
	    
	    add(labelId);
	    add(labelPass);
	    add(fieldPass);
	    add(btn);
	    
	    btn.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	privateKey = null;
				try {
					java.util.Iterator<PGPSecretKey> iterPriv = secretKeyRing.getSecretKeys();
	            	PGPSecretKey masterKey = iterPriv.next();
	            	PGPSecretKey secretKey = iterPriv.next();
					privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
							.setProvider("BC").build(fieldPass.getText().toCharArray()));
				} catch (PGPException e2) {
					kgh.writeMessage("Pogresna lozinka");
					return;
				}
            	 if(privateKey!=null && delete) { 
            		 try {
						kgh.DeleteSecretKeyPair(id);
					} catch (PGPException e1) {
						e1.printStackTrace();
					}
            	 }
            	 if (!delete)
            	 {
            		 try {
						msgSender.continueWithDecryption(privateKey);
					} catch (PGPException e1) {
						kgh.writeMessage("Doslo je do greske vezano sa PGP protokolom");
						e1.printStackTrace();
					} catch (IOException e1) {
						kgh.writeMessage("Doslo je do neocekivane greske prilikom rada sa fajlom.");
						e1.printStackTrace();
					}
            	 }
            	 dispose();
            }
        });
	}
}
