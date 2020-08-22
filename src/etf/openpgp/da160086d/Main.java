package etf.openpgp.da160086d;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

public class Main {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		GUIwindow mainWindow = null;
		try {
			mainWindow = new GUIwindow("Glavni meni");
		} catch (IOException | PGPException e) {
			e.printStackTrace();
		}
		mainWindow.setVisible(true);
	}

}
