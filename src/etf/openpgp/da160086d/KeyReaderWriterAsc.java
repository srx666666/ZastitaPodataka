package etf.openpgp.da160086d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays.Iterator;

public class KeyReaderWriterAsc {
	
	private KeyGeneratorHelper keyGenHelper;

	KeyReaderWriterAsc(KeyGeneratorHelper kgh)
	{
		keyGenHelper = kgh;
	}
	
	public void Read(String filePath) throws IOException, PGPException
	{
		File file = new File(filePath);
		InputStream is = new FileInputStream(file);
		
		PGPSecretKeyRingCollection pgpSec = 
				new PGPSecretKeyRingCollection( PGPUtil.getDecoderStream( is ), new JcaKeyFingerprintCalculator() );
		
		java.util.Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
		PGPSecretKeyRing keyRing = ( PGPSecretKeyRing ) keyRingIter.next();
		keyGenHelper.AddAndSaveAllSecrets(keyRing);
	}
}
