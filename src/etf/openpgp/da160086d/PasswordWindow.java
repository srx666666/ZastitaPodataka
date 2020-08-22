package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PasswordWindow extends JFrame{

	private JLabel labelPass;
	private JTextField fieldPass;
	private JButton btn;
	private PGPSecretKeyRing secretKeyRing;
	private boolean delete;
	private PGPPrivateKey privateKey = null;
	
	public PasswordWindow(String name, long id, KeyGeneratorHelper kgh, boolean del) {
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
					privateKey = secretKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
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
            	 dispose();
            }
        });
	}
	
	
	public PGPPrivateKey GetPrivateKey()
	{
		for (int i=0;i< 30;i++)
		{
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			if (privateKey!=null)
				break;
		}
		return privateKey;
	}
}
