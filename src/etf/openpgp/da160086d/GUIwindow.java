package etf.openpgp.da160086d;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

public class GUIwindow extends JFrame {
	private JButton genKey, inOutKey, showKeys, sendMsg, rcvMsg; 
	
	public GUIwindow (String name)
	{
		super(name);
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
	    
	    setLayout( new GridLayout(5, 1) );
	    
	    genKey = new JButton("Generisanje novog kljuca");
	    inOutKey = new JButton("Uvoz/izvoz kljuca");
	    showKeys = new JButton("Prikaz postojecih kljuceva");
	    sendMsg = new JButton("Posalji poruku");
	    rcvMsg = new JButton("Primljene poruke");
	    
	    AddActionsToButtons();
	    
	    add(genKey);
	    add(inOutKey);
	    add(showKeys);
	    add(sendMsg);
	    add(rcvMsg);
	}
	
	
	private void AddActionsToButtons()
	{
		GenKeyWindow gkw = new GenKeyWindow("Generisanje kljuceva");
		genKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	 gkw.setVisible(true);
            }
        });
	}
}
