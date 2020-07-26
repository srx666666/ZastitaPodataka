package etf.openpgp.da160086d;

import java.awt.Color;
import java.awt.Container;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Panel;

import javax.swing.ButtonGroup;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class GenKeyWindow extends JFrame {
	
	 private JLabel labelName, labelMail, labelSifra, labelRSA1024, labelRSA2048, labelRSA4096; 
	 private JLabel labelAES, labelTripleDES;
	 private JTextField tname, tmail, tsifra;
	 private JPanel panel;
	 private Container c;
	 private JRadioButton rsa1024, rsa2048, rsa4096, desEde, aes;
	 private ButtonGroup algorithmSelect;
	
	 public GenKeyWindow (String name)
	 {
		super(name);
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
	    
	    setLayout( new GridLayout(8, 2) );
	    
	    labelName = new JLabel ("Ime kljuca");
	    labelMail = new JLabel("Mail");
	    labelSifra = new JLabel("Sifra");
	    labelRSA1024 = new JLabel("RSA1024");
	    labelRSA2048 = new JLabel("RSA2048");
	    labelRSA4096 = new JLabel("RSA4096");
	    labelTripleDES = new JLabel("Triple DES");
	    labelAES = new JLabel("AES");
	    
	    tname = new JTextField(); 
	    tname.setSize(190, 30); 
	    tmail = new JTextField();
	    tmail.setSize(190,30);
	    tsifra = new JTextField();
	    tsifra.setSize(190,30);
	    
	    rsa1024 = new JRadioButton();
	    rsa2048 = new JRadioButton();
	    rsa4096 = new JRadioButton();
	    aes = new JRadioButton();
	    desEde = new JRadioButton();
	    
	    algorithmSelect = new ButtonGroup();
	    algorithmSelect.add(rsa1024);
	    algorithmSelect.add(rsa2048);
	    algorithmSelect.add(rsa4096);
	    algorithmSelect.add(aes);
	    algorithmSelect.add(desEde);
	    
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
	    add (labelTripleDES);
	    add (desEde);
	    add (labelAES);
	    add (aes);
	 }
	 
	/*public GenKeyWindow (String name)
	{
		super(name);
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
	    
	    getContentPane().setBackground(Color.WHITE);
	    
	    panel = new JPanel();
	    
	    c = getContentPane(); 
        c.setLayout(null);
	    
	    lname = new JLabel("Ime"); 
        lname.setFont(new Font("Arial", Font.PLAIN, 20)); 
        lname.setSize(100, 20); 
        lname.setLocation(100, 100); 
        c.add(lname); 
  
        tname = new JTextField(); 
        tname.setFont(new Font("Arial", Font.PLAIN, 15)); 
        tname.setSize(190, 30); 
        tname.setLocation(200, 100); 
        c.add(tname);
        
        
	    lmail = new JLabel("E-mail");
        lmail.setFont(new Font("Arial", Font.PLAIN, 20)); 
        lmail.setSize(100, 20); 
        lmail.setLocation(100, 150); 
        c.add(lmail); 
  
        tmail = new JTextField(); 
        tmail.setFont(new Font("Arial", Font.PLAIN, 15)); 
        tmail.setSize(190, 30); 
        tmail.setLocation(200, 150); 
        c.add(tmail);
        
        asymetric = new JTextArea("Asimetricni : "); 
        asymetric.setText("Asimetricni : ");
        asymetric.setFont(new Font("Arial", Font.PLAIN, 20)); 
        asymetric.setSize(100, 20); 
        asymetric.setLocation(100, 200); 
        c.add(asymetric); 
  
        rsa1024 = new JRadioButton("RSA 1024 bita"); 
        rsa1024.setFont(new Font("Arial", Font.PLAIN, 15)); 
        rsa1024.setSelected(true); 
        rsa1024.setSize(75, 20); 
        rsa1024.setLocation(200, 200); 
        c.add(rsa1024); 
  
        rsa2048 = new JRadioButton("RSA 2048 bita"); 
        rsa2048.setFont(new Font("Arial", Font.PLAIN, 15)); 
        rsa2048.setSelected(true); 
        rsa2048.setSize(75, 20); 
        rsa2048.setLocation(200, 250); 
        c.add(rsa2048); 
        
        rsa4096 = new JRadioButton("RSA 4096 bita"); 
        rsa4096.setFont(new Font("Arial", Font.PLAIN, 15)); 
        rsa4096.setSelected(true); 
        rsa4096.setSize(75, 20); 
        rsa4096.setLocation(200, 300); 
        c.add(rsa4096); 
  
        asym = new ButtonGroup(); 
        asym.add(rsa1024); 
        asym.add(rsa2048);
        asym.add(rsa4096);
        
        /*symetric = new JLabel("Simetricni"); 
        symetric.setFont(new Font("Arial", Font.PLAIN, 20)); 
        symetric.setSize(100, 20); 
        symetric.setLocation(100, 200); 
        c.add(symetric);*/
	//}
}
