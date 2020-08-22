package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;

public class ExportKeyWindow extends JFrame{
	
	private JRadioButton publ, priv;
	private ButtonGroup btnSelect;
	private JLabel labelId, labelPath, labelPubl, labelPriv;
	private JTextField tId, tPath;
	private JButton btn;
	private KeyReaderWriterAsc keyReaderWriter;
	
	public ExportKeyWindow(String name, KeyReaderWriterAsc krw, KeyGeneratorHelper keyGenHelper) {
		super(name);
		keyReaderWriter = krw;
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    setLayout( new GridLayout(5, 2) );
	    
	    labelId = new JLabel("ID : ");
	    tId = new JTextField(); 
	    tId.setSize(190, 30);
	    labelPath = new JLabel("Putanja : ");
	    tPath = new JTextField(); 
	    tPath.setSize(190, 30);
	    labelPubl = new JLabel("Javni");
	    labelPriv = new JLabel("Privatni");
	    publ = new JRadioButton();
	    priv = new JRadioButton();
	    
	    btnSelect = new ButtonGroup();
	    btnSelect.add(publ);
	    btnSelect.add(priv);
	    
	    btn = new JButton("Gotovo");
	    
	    add(labelId);
	    add(tId);
	    add(labelPath);
	    add(tPath);
	    add(labelPubl);
	    add(publ);
	    add(labelPriv);
	    add(priv);
	    add(btn);
	    
	    btn.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	if (publ.isSelected())
					try {
						keyReaderWriter.WritePublic(tPath.getText(), Long.parseLong(tId.getText()));
					} catch (NumberFormatException e1) {
						keyGenHelper.writeMessage("Format keyId mora biti broj.");
					} catch (IOException e1) {
						keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
					}
            	if (priv.isSelected())
					try {
						keyReaderWriter.WritePrivate(tPath.getText(), Long.parseLong(tId.getText()));
					} catch (IOException e1) {
						keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
					}
            }
        });
	}
}
