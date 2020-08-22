package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class KeysWindow extends JFrame{
	
	private JButton btn;
	private int startPublic = 0;
	private int startPrivate = 0;
	private int n=5;
	private JTextField field[][];
	private KeyGeneratorHelper keyGenHelper;
	JRadioButton publicKeys;
    JRadioButton privateKeys;
	
	public KeysWindow(String name, KeyGeneratorHelper kgh) {
		super(name);
		keyGenHelper = kgh;
		setSize( 800, 500 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    
	    field= new JTextField[n][3];
	    
	    setLayout( new GridLayout(n + 5, 3) );
	    
	    JLabel keyId = new JLabel("keyId");
	    this.add(keyId);
	    
	    JLabel keyOwnerId = new JLabel("keyOwnerId");
	    this.add(keyOwnerId);
	    
	    JLabel privateKeyId = new JLabel("vreme");
	    this.add(privateKeyId);
	    
	    
	    for (int i=0; i<n ;i++) {
	    	for (int j=0;j<3 ;j++)
	    	{
	    		field[i][j] = new JTextField();
	    		this.add(field[i][j]);
	    	}
	    }
	    
	    btn = new JButton("Zavrseno");
	    
	    btn.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	 dispose();
            }
        });
	    this.add(btn);
	    
	    JButton nextKey = new JButton("Sledeci");
	    nextKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
             if (privateKeys.isSelected())
             {
            	 startPrivate++;
             }
             else
             {
            	 startPublic++;
             }
           	 osvezi();
            }
        });
	    this.add(nextKey);
	    
	    JButton prevKey = new JButton("Prethodni");
	    prevKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
             if (privateKeys.isSelected())
             {
	             startPrivate--;
	             if (startPrivate < 0)
	            	 startPrivate = 0;
             }
             else
             {
            	 startPublic--;
	             if (startPublic < 0)
	            	 startPublic = 0;
             }
           	 osvezi();
            }
        });
	    this.add(prevKey);
	    
	    JTextField delWho = new JTextField();
	    JLabel empty = new JLabel();
	    JLabel empty2 = new JLabel();
    	
    	JButton del= new JButton("Obrisi");
    	del.addActionListener(new ActionListener() {
    			   public void actionPerformed(ActionEvent e) { 
    				   if (privateKeys.isSelected())
    				   {
    					   long id = 0;
    					   try {
    						   id = Long.parseLong(delWho.getText());
    					   } catch (NumberFormatException e1) {
   							kgh.writeMessage("Format keyId za brisanje mora biti broj.");
   							return;
   							} 
	    				   PasswordWindow passw = new PasswordWindow("Lozinka za kljuc", id,keyGenHelper, true);
	    				   passw.setVisible(true);   //proveri kako da posaljes koji tacno kljuc hoces da obrises
    				   }
    				   if (publicKeys.isSelected())
    				   {
    					   try {
							keyGenHelper.DeletePublicKey(Long.parseLong(delWho.getText()));
						} catch (NumberFormatException e1) {
							kgh.writeMessage("Format keyId za brisanje mora biti broj.");
						} catch (PGPException e1) {
							e1.printStackTrace();
						}
    				   }
    			   }
    	});
    	
    	this.add(del);
    	this.add(delWho);
    	this.add(empty);
    	
    	publicKeys = new JRadioButton();
	    privateKeys = new JRadioButton();
	    ButtonGroup typeSelect = new ButtonGroup();
	    typeSelect.add(publicKeys);
	    typeSelect.add(privateKeys);
	    JLabel publicLabel = new JLabel("Public keys");
	    JLabel privateLabel = new JLabel("Private keys");
    	
	    this.add(privateLabel);
	    this.add(privateKeys);
	    this.add(empty2);
	    this.add(publicLabel);
	    this.add(publicKeys);
	    
	    JButton refresh= new JButton("Osvezi");
    	refresh.addActionListener(new ActionListener() {
    			   public void actionPerformed(ActionEvent e) { 
    				   osvezi();
    			   }
    	});
    	
    	this.add(refresh);
	}
	    
	private void osvezi()
	{
		if (privateKeys.isSelected())
		{
			int curPosition=0;
			for (int i=startPrivate;i<startPrivate+n;i++)
			{
				PGPSecretKeyRing keyRing = keyGenHelper.GetPrivateKeyByPosition(i);
				if (keyRing == null)
				{
					for (int j = curPosition;j<n;j++)
					{
						field[j][0].setText("");
						field[j][1].setText("");
						field[j][2].setText("");
					}
					
					break;
				}
				
				java.util.Iterator<PGPPublicKey> iterPublic = keyRing.getPublicKeys();
				PGPPublicKey masterKey = iterPublic.next();
				PGPPublicKey publicKey= iterPublic.next();
				java.util.Iterator<PGPSecretKey> iterPrivate = keyRing.getSecretKeys();
				PGPSecretKey privateKey = iterPrivate.next();
				privateKey = iterPrivate.next();
				field[curPosition][0].setText(String.valueOf(publicKey.getKeyID()));
				field[curPosition][1].setText(masterKey.getUserIDs().next());
				field[curPosition][2].setText(String.valueOf(publicKey.getCreationTime()));
				curPosition++;
			}
		}
		if (publicKeys.isSelected())
		{
			int curPosition=0;
			for (int i=startPublic;i<startPublic+n;i++)
			{
				PGPPublicKeyRing keyRing = keyGenHelper.GetPublicKeyByPosition(i);
				if (keyRing == null)
				{
					for (int j = curPosition;j<n;j++)
					{
						field[j][0].setText("");
						field[j][1].setText("");
						field[j][2].setText("");
					}
					break;
				}
				
				java.util.Iterator<PGPPublicKey> iterPublic = keyRing.getPublicKeys();
				PGPPublicKey masterKey = iterPublic.next();
				PGPPublicKey publicKey= iterPublic.next();
				field[curPosition][0].setText(String.valueOf(publicKey.getKeyID()));
				field[curPosition][1].setText(masterKey.getUserIDs().next());
				field[curPosition][2].setText(String.valueOf(publicKey.getCreationTime()));
				curPosition++;
			}
		}
	}
}
