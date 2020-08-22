package etf.openpgp.da160086d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;

public class ImportExportKeysWindow extends JFrame{
	
	private JButton importKey, exportKey;
	
	public ImportExportKeysWindow (String name, KeyGeneratorHelper kgh){
		super(name);
		setSize( 500, 500 );
	    setDefaultCloseOperation( JFrame.DISPOSE_ON_CLOSE );
	    
	    setLayout( new GridLayout(2, 1) );
	    
	    importKey = new JButton("Uvoz javnog/privatnog kljuca");
	    exportKey = new JButton("Izvoz javnog/privanog kljuca");
	    
	    add(importKey);
	    add(exportKey);
	    
	    ImportKeyWindow ikw = new ImportKeyWindow("Uvoz kljuca", new KeyReaderWriterAsc(kgh), kgh);
	    ExportKeyWindow ekw = new ExportKeyWindow("Izvoz kljuca", new KeyReaderWriterAsc(kgh), kgh);
	    
	    importKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	 ikw.setVisible(true);
            }
        });
	    
	    exportKey.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
            	 ekw.setVisible(true);
            }
        });	    
	}
}
