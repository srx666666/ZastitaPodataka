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

public class ImportKeyWindow extends JFrame{

	private JRadioButton publ, priv;
	private ButtonGroup btnSelect;
	private JLabel labelPath, labelPriv, labelPubl;
	private JTextField tPath;
	private JButton btn;
	private KeyReaderWriterAsc keyReaderWriter;
	
	public ImportKeyWindow(String name, KeyReaderWriterAsc krw, KeyGeneratorHelper keyGenHelper) {
		super(name);
		keyReaderWriter = krw;
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    setLayout( new GridLayout(5, 2) );
	    
	    labelPath = new JLabel("Putanja : ");
	    tPath = new JTextField(); 
	    tPath.setSize(190, 30);
	    labelPriv = new JLabel("Privatni");
	    labelPubl = new JLabel("Javni");
	    publ = new JRadioButton();
	    priv = new JRadioButton();
	    
	    btnSelect = new ButtonGroup();
	    btnSelect.add(publ);
	    btnSelect.add(priv);
	    
	    btn = new JButton("Gotovo");
	    
	    add(labelPath);
	    add(tPath);
	    add(publ);
	    add(labelPubl);
	    add(priv);
	    add(labelPriv);
	    add(btn);
	    
	    btn.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	if (publ.isSelected())
					try {
						keyReaderWriter.ReadPublic(tPath.getText());
					} catch (PGPException e1) {
						keyGenHelper.writeMessage("Doslo je do neocekivane greske u radu sa PGP protokolom.");
					} catch (IOException e1) {
						keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
					}
            	if (priv.isSelected())
					try {
						keyReaderWriter.ReadPrivate(tPath.getText());
					} catch (PGPException e1) {
						keyGenHelper.writeMessage("Doslo je do neocekivane greske u radu sa PGP protokolom.");
					} catch (IOException e1) {
						keyGenHelper.writeMessage("Doslo je do greske prilikom rada sa fajlom");
					}
            }
        });
	}
	
}
