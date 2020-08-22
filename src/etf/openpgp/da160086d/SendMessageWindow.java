package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class SendMessageWindow extends JFrame{

	private KeyGeneratorHelper keyGenHelper;
	private MessageSender messageSender;
	private ArrayList<PGPPublicKey> publicKeys = new ArrayList<PGPPublicKey>();
	
	public SendMessageWindow(String name, KeyGeneratorHelper kgh, MessageSender ms) {
		super(name);
		
		setSize( 500, 800 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    setLayout( new GridLayout(13, 2) );
		keyGenHelper = kgh;
		messageSender = ms;
		
		JLabel sourcePath = new JLabel("Putanja do poruke za slanje");
		JLabel targetPath = new JLabel("Putanja na koju se poruka salje");
		JTextField sourcePathInput = new JTextField();
		JTextField targetPathInput = new JTextField();
		
		this.add(sourcePath);
		this.add(sourcePathInput);
		this.add(targetPath);
		this.add(targetPathInput);
		
		JLabel encrytKeyIdLabel = new JLabel ("Id kljuca za enkripciju");
		JTextField encryptKeyId = new JTextField();
		
		JButton addEncryptKey = new JButton("Dodaj kljuc");
		addEncryptKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	PGPPublicKeyRing keyRing = keyGenHelper.GetPublicKeyById(Long.parseLong(encryptKeyId.getText()));
            	if (keyRing != null)
            	{
            		java.util.Iterator<PGPPublicKey> iterPublic = keyRing.getPublicKeys();
            		PGPPublicKey masterKey = iterPublic.next();
            		PGPPublicKey publicKey = iterPublic.next();
            		publicKeys.add(publicKey);
            		keyGenHelper.writeMessage("Uspesno ste dodali kljuc "+encryptKeyId.getText());
            	}
            	else
            	{
            		keyGenHelper.writeMessage("Ne postoji kljuc sa zadatim id-om.");
            	}
           }
        });
		JLabel empty= new JLabel("");
		
		this.add(encrytKeyIdLabel);
		this.add(encryptKeyId);
		this.add(addEncryptKey);
		this.add(empty);
		
		JLabel signLabel = new JLabel("Id kljuca za potpis");
		JTextField sign = new JTextField();
		JLabel signPassword = new JLabel("Sifra do kljuca za potpis");
		JTextField password = new JTextField();
		
		this.add(signLabel);
		this.add(sign);
		this.add(signPassword);
		this.add(password);
		
		JLabel aesLabel = new JLabel("AES enkripcija");
		JRadioButton aes = new JRadioButton();
		JLabel desLabel = new JLabel("3DES enkripcija");
		JRadioButton des = new JRadioButton();
		ButtonGroup algorithm = new ButtonGroup();
		algorithm.add(aes);
		algorithm.add(des);
		
		this.add(aesLabel);
		this.add(aes);
		this.add(desLabel);
		this.add(des);
		
		JLabel encLabel = new JLabel ("Enkripcija");
		JLabel sigLabel = new JLabel ("Potpis");
		JLabel compressLabel = new JLabel ("Zip kompresija");
		JLabel radixLabel = new JLabel ("radix64");
		JCheckBox enc = new JCheckBox();
		JCheckBox sig = new JCheckBox();
		JCheckBox compress = new JCheckBox();
		JCheckBox radix = new JCheckBox();
		
		this.add(encLabel);
		this.add(enc);
		this.add(sigLabel);
		this.add(sig);
		this.add(compressLabel);
		this.add(compress);
		this.add(radixLabel);
		this.add(radix);
		
		JButton send = new JButton("Posalji");
		send.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	int encryptionAlgorithm= -1;
            	if (aes.isSelected())
            	{
            		encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
            	}
            	if (des.isSelected())
            	{
            		encryptionAlgorithm = SymmetricKeyAlgorithmTags.TRIPLE_DES;
            	}
            	
            	if (enc.isSelected() && encryptionAlgorithm==-1) 
            	{
            		keyGenHelper.writeMessage("Nije selektovan algoritam za enkripciju");
            		return;
            	}
            	
            	PGPPublicKey[] publicKeysArr = new PGPPublicKey[publicKeys.size()];
            	publicKeys.toArray(publicKeysArr);
            	
            	Long signature;
            	try {
            		signature = Long.parseLong(sign.getText());
            	}
            	catch (Exception e1)
            	{
            		signature = (long) 0;
            	}
            	try {
					messageSender.sendMessage(sourcePathInput.getText(),targetPathInput.getText(), publicKeysArr,
							signature, password.getText().toCharArray(), enc.isSelected(), sig.isSelected(),compress.isSelected(),
							radix.isSelected(), encryptionAlgorithm);
					
					File targetFile = new File(targetPathInput.getText());
					if (targetFile.exists())
					{
						keyGenHelper.writeMessage("Poruka poslata.");
					}
				} catch (NumberFormatException e1) {
					keyGenHelper.writeMessage("KeyId nije u dobrom formatu.");
				} catch (PGPException e1) {
					keyGenHelper.writeMessage("Doslo je do neocekivane greske u radu sa PGP protokolom.");
				} catch (IOException e1) {
					keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
				}
            }
        });
		
		this.add(send);
	}

}
