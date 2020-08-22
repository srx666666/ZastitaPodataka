package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

public class ReceiveMessageWindow extends JFrame{
	private KeyGeneratorHelper keyGenHelper;
	private MessageSender messageSender;
	private ArrayList<PGPPublicKey> publicKeys = new ArrayList<PGPPublicKey>();
	
	public ReceiveMessageWindow(String name, KeyGeneratorHelper kgh, MessageSender ms) {
		super(name);
		
		setSize( 500, 400 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    setLayout( new GridLayout(3, 2) );
		keyGenHelper = kgh;
		messageSender = ms;
		
		JLabel sourcePath = new JLabel("Putanja do poruke za dekripciju");
		JLabel targetPath = new JLabel("Putanja do dekriptovane poruke");
		JTextField sourcePathInput = new JTextField();
		JTextField targetPathInput = new JTextField();
		
		this.add(sourcePath);
		this.add(sourcePathInput);
		this.add(targetPath);
		this.add(targetPathInput);
		
		/*JLabel signPassword = new JLabel("Sifra do kljuca za enkripciju");
		JTextField password = new JTextField();
		this.add(signPassword);
		this.add(password);*/
		
		JButton receive = new JButton("Prijem");
		receive.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	try {
					messageSender.receiveMessage(sourcePathInput.getText(), targetPathInput.getText(), 
							true);
					keyGenHelper.writeMessage("Uspesno je primljena poruka");
				} catch (PGPException e1) {
					keyGenHelper.writeMessage("Doslo je do neocekivane greske u radu sa PGP protokolom.");
				} catch (IOException e1) {
					keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
				}
            }
        });
		
		this.add(receive);
	}
}
