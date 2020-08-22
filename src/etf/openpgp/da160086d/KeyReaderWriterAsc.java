package etf.openpgp.da160086d;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
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
	
	public void ReadPrivate(String filePath) throws IOException, PGPException
	{
		File file = new File(filePath);
		InputStream is = new FileInputStream(file);
		
		PGPSecretKeyRing keyRing = 
				new PGPSecretKeyRing( PGPUtil.getDecoderStream( is ), new JcaKeyFingerprintCalculator() );
		
		keyGenHelper.AddAndSavePrivateSecrets(keyRing);
	}
	
	public void ReadPublic(String filePath) throws IOException, PGPException
	{
		File file = new File(filePath);
		InputStream is = new FileInputStream(file);
		
		PGPPublicKeyRing keyRing = 
				new PGPPublicKeyRing( PGPUtil.getDecoderStream( is ), new JcaKeyFingerprintCalculator() );
		
		keyGenHelper.AddAndSavePublicSecrets(keyRing);
	}
	
	public boolean WritePublic(String filePath, long id) throws IOException
	{
		PGPPublicKeyRing keyRing = keyGenHelper.GetPublicKeyById(id);
		if (keyRing == null)
		{
			keyGenHelper.writeMessage("Trazeni kljuc ne postoji");
			return false;
		}
		
    	ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
		keyRing.encode(secretOut);
		secretOut.close();
		
    	File secretsFile = new File(filePath);
		if (secretsFile.exists())
			secretsFile.delete();
		
		try(OutputStream outputStream = new FileOutputStream(filePath)) {
		    secretOut.writeTo(outputStream);
		}
		
		return true;
	}
	
	public boolean WritePrivate(String filePath, long id) throws IOException
	{
		PGPSecretKeyRing keyRing = keyGenHelper.GetPrivateKeyById(id);
		if (keyRing == null)
		{
			keyGenHelper.writeMessage("Trazeni kljuc ne postoji");
			return false;
		}
		
    	ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
		keyRing.encode(secretOut);
		secretOut.close();
		
    	File secretsFile = new File(filePath);
		if (secretsFile.exists())
			secretsFile.delete();
		
		try(OutputStream outputStream = new FileOutputStream(filePath)) {
		    secretOut.writeTo(outputStream);
		}
		
		return true;
	}
}
