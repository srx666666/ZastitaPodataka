package etf.openpgp.da160086d;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.*;

import org.bouncycastle.openpgp.PGPException;

public class GUIwindow extends JFrame {
	private JButton genKey, inOutKey, showDelKeys, sendMsg, rcvMsg, delKeys; 
	private JTextArea messageBoard;
	
	public GUIwindow (String name) throws IOException, PGPException
	{
		super(name);
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
	    
	    setLayout( new GridLayout(6, 1) );
	    
	    genKey = new JButton("Generisanje novog kljuca");
	    inOutKey = new JButton("Uvoz/izvoz kljuca");
	    sendMsg = new JButton("Posalji poruku");
	    rcvMsg = new JButton("Primljene poruke");
	    showDelKeys = new JButton("Prikaz i brisanje postojeceg para kljuceva");
	    
	    KeyGeneratorHelper keyGenHelper = new KeyGeneratorHelper("C:\\Users\\srdjn\\Desktop\\keys\\privateRing.bin","C:\\Users\\srdjn\\Desktop\\keys\\publicRing.bin", this);
	    AddActionsToButtons(keyGenHelper);
	    
	    add(genKey);
	    add(showDelKeys);
	    add(inOutKey);
	    add(sendMsg);
	    add(rcvMsg);
	    
	    messageBoard = new JTextArea();
	    add(messageBoard);
	}
	
	
	private void AddActionsToButtons(KeyGeneratorHelper keyGenHelper)
	{
		GenKeyWindow gkw = new GenKeyWindow("Generisanje kljuceva", keyGenHelper);
		genKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	 gkw.setVisible(true);
            }
        });
		
		KeysWindow kw = new KeysWindow("Prikaz i brisanje postojeceg para kljuceva", keyGenHelper);
		showDelKeys.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				kw.setVisible(true);
			}
		});
		
		ImportExportKeysWindow iekw = new ImportExportKeysWindow("Uvozi/izvoz kljuceva", keyGenHelper);
		inOutKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				iekw.setVisible(true);
			}
		});
		
		SendMessageWindow sendMes = new SendMessageWindow("Posalji poruku", keyGenHelper, new MessageSender(keyGenHelper));
		sendMsg.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendMes.setVisible(true);
			}
		});
		
		ReceiveMessageWindow recMes = new ReceiveMessageWindow("Primi poruku", keyGenHelper, new MessageSender(keyGenHelper));
		rcvMsg.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				recMes.setVisible(true);
			}
		});
	}
	
	public void writeMessage(String message)
	{
		messageBoard.setText(message);
		System.out.println(message);
	}
}
