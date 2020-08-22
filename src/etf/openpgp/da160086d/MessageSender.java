package etf.openpgp.da160086d;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays.Iterator;

public class MessageSender {
	
	private KeyGeneratorHelper keyGenHelper;

	MessageSender(KeyGeneratorHelper kgh)
	{
		keyGenHelper = kgh;
	}
	
	public void sendMessage(String sourceFilePath, String targetFilePath, PGPPublicKey[] encryptionKeys, long keySignId, char[] pass,
			boolean encrypt, boolean sign, boolean zip, boolean toRadix, int encryptionAlgorithm) throws PGPException, IOException
	{
		byte[] allBytes = null;
        
        // sign
        //
        if (sign == true)
        {
        	System.out.println("Signed");
        	PGPSecretKeyRing privateKeyRing = keyGenHelper.GetPrivateKeyById(keySignId);
        	
        	if (privateKeyRing == null)
        	{
        		keyGenHelper.writeMessage("Ne postoji kljuc za potpisivanje.");
        		return;
        	}
        	
        	java.util.Iterator<PGPSecretKey> iterPriv = privateKeyRing.getSecretKeys();
        	PGPSecretKey masterKey = iterPriv.next();
        	PGPSecretKey secretKey = iterPriv.next();
        	PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        	PGPPrivateKey masterPrivateKey = masterKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        	PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(privateKeyRing.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
        	
        	ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            BCPGOutputStream helperStream = new BCPGOutputStream(byteStream);
            
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, masterPrivateKey);
            signatureGenerator.generateOnePassVersion(false).encode(helperStream);
            
            File                        file = new File(sourceFilePath);
            PGPLiteralDataGenerator     lGen = new PGPLiteralDataGenerator();
            OutputStream                lOut = lGen.open(helperStream, PGPLiteralData.BINARY, file);
            FileInputStream             fIn = new FileInputStream(file);
            int                         ch;
            
            while ((ch = fIn.read()) >= 0)
            {
                lOut.write(ch);
                signatureGenerator.update((byte)ch);
            }
            
            lGen.close();

            signatureGenerator.generate().encode(helperStream);

            allBytes = byteStream.toByteArray();
            
            fIn.close();
            byteStream.close();
            helperStream.close();
        }
        else
        {
        	// read the file
    		//
            try (InputStream inputStream = new FileInputStream(sourceFilePath);) 
            {
                long fileSize = new File(sourceFilePath).length();
     
                allBytes = new byte[(int) fileSize];
     
                allBytes = inputStream.readAllBytes();
     
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        
        // compression
        //
        if (zip == true)
        {
        	System.out.println("zipped");
        	ByteArrayOutputStream helperOutputStream = new ByteArrayOutputStream();
        	PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        	OutputStream compressedOutputStream = comData.open(helperOutputStream);
        	compressedOutputStream.write(allBytes);
        	compressedOutputStream.close();
        	
        	allBytes = helperOutputStream.toByteArray();
        	
        	helperOutputStream.close();
        }
        
        // encryption
        //
        if (encrypt == true)
        {
        	System.out.println("encrypted");
        	PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(encryptionAlgorithm)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC")
            );
        	
        	if (encryptionKeys.length == 0)
        	{
        		keyGenHelper.writeMessage("Nema izabranih kljuceva za enkripciju.");
        		return;
        	}
        	for (PGPPublicKey encryptionKey : encryptionKeys) {
                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));
            }
        	
	        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	        OutputStream encryptedOutputStream = encryptedDataGenerator.open(outputStream, allBytes.length);
	        encryptedOutputStream.write(allBytes);
	        encryptedOutputStream.close();
	        allBytes = outputStream.toByteArray();
	        
	        outputStream.close();
        }
        
        if (toRadix == true)
        {
        	System.out.println("to radix64");
        	ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(byteOutputStream);
            armoredOutputStream.write(allBytes);
            armoredOutputStream.close();
            allBytes = byteOutputStream.toByteArray();
            
            byteOutputStream.close();
        }
        
    	OutputStream outputStream = new FileOutputStream(targetFilePath);
    	outputStream.write(allBytes);
	}
	
	public void receiveMessage(String sourceFilePath, String targetFilePath, boolean radix64) throws IOException, PGPException
	{
		byte[] allBytes = null;
		int maxByteSize = 0;
		try (InputStream inputStream = new FileInputStream(sourceFilePath);) 
        {
            long fileSize = new File(sourceFilePath).length();
            maxByteSize = (int) (fileSize * 10);
 
            allBytes = new byte[(int) fileSize];
 
            allBytes = inputStream.readAllBytes();
 
        } catch (IOException ex) {
            ex.printStackTrace();
        }
		
		File file = new File(sourceFilePath);
        byte[] data = Files.readAllBytes(file.toPath());
		
		if (radix64)
		{
			try {
				ByteArrayInputStream byteInputStream = new ByteArrayInputStream(allBytes);
		        InputStream inputStream = PGPUtil.getDecoderStream(byteInputStream);
		        inputStream.close();
		        allBytes = inputStream.readAllBytes();
		        
		        byteInputStream.close();
			}
			catch (Exception e)
			{
				keyGenHelper.writeMessage("Radix 64 conversion failed.");
			}
		}
		
		PGPEncryptedDataList enc;
		PGPObjectFactory objectFactory = new JcaPGPObjectFactory(allBytes);
		Object o = null;
		try
		{
			o = objectFactory.nextObject();
		}
		catch (Exception e)
		{
			OutputStream outputStream = new FileOutputStream(targetFilePath);
        	outputStream.write(allBytes);
        	
        	return;
		}
		
		if (o instanceof PGPEncryptedDataList) 
		{
		    enc = (PGPEncryptedDataList) o;
			java.util.Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
		    PGPPrivateKey sKey = null;
		    PGPPublicKeyEncryptedData pbe = null;
		    while (sKey == null && it.hasNext())
		    {
		        pbe = (PGPPublicKeyEncryptedData) it.next();
	            PGPSecretKeyRing keyRing = keyGenHelper.GetPrivateKeyById(pbe.getKeyID());
	            
	            if (keyRing != null)
	            {
	            	java.util.Iterator<PGPSecretKey> iterPriv = keyRing.getSecretKeys();
	            	PGPSecretKey masterKey = iterPriv.next();
	            	PGPSecretKey secretKey = iterPriv.next();
	            	PasswordWindow passWindow = new PasswordWindow("Unesite sifru", pbe.getKeyID(), keyGenHelper, false);
	            	passWindow.setVisible(true);
			        PGPPrivateKey privateKey = passWindow.GetPrivateKey();
			        if (privateKey == null)
			        {
			        	keyGenHelper.writeMessage("Potpis nije propisno unesen");
			        }
			        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
	                InputStream inputStream = pbe.getDataStream(dataDecryptorFactory);
	                allBytes = inputStream.readAllBytes();
	                
	                inputStream.close();
	                
	                objectFactory = new JcaPGPObjectFactory(allBytes);
	    			o = null;
	    			try
	    			{
	    				o = objectFactory.nextObject();
	    			}
	    			catch (Exception e)
	    			{
	    				OutputStream outputStream = new FileOutputStream(targetFilePath);
	    	        	outputStream.write(allBytes);
	    	        	
	    	        	return;
	    			}
	            }
	            else
	            {
	            	keyGenHelper.writeMessage("Nije pronadjen kljuc za dekripciju.");
	            	return;
	            }
		    }
		}
		
		if (o instanceof PGPCompressedData) 
		{
			try
			{
				InputStream inputStream = ((PGPCompressedData)o).getDataStream();
				allBytes = inputStream.readAllBytes();
				
				inputStream.close();
			}
			catch (PGPException e)
			{
				keyGenHelper.writeMessage("Greska prilikom dekompresije.");
				return;
			}
			objectFactory = new JcaPGPObjectFactory(allBytes);
			o = null;
			try
			{
				o = objectFactory.nextObject();
			}
			catch (Exception e)
			{
				OutputStream outputStream = new FileOutputStream(targetFilePath);
	        	outputStream.write(allBytes);
	        	
	        	return;
			}
		}
		
		if (o instanceof PGPOnePassSignatureList) 
		{
			PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) o;
            PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

            long keyId = onePassSignature.getKeyID();
            PGPPublicKeyRing keyRing = keyGenHelper.GetPublicMasterKeyById(keyId);
            PGPPublicKey publicKey = null;
            if (keyRing != null)
            {
            	java.util.Iterator<PGPPublicKey> iterPublic = keyRing.getPublicKeys();
        		publicKey = iterPublic.next();
            }
            else
            {
            	keyGenHelper.writeMessage("Nije pronadjen kljuc za verifikaciju potpisa.");
            	return;
            }
            
            PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
            
            onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

            byte[] verificationBytes = new byte[maxByteSize];
            verificationBytes = literalData.getInputStream().readAllBytes();
            byte[] outputBytes = verificationBytes.clone();
            
            for (int i= 0; i< verificationBytes.length; i++) {
                onePassSignature.update(verificationBytes[i]);
            }

            PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
            PGPSignature signature = signatureList.get(0);

            if (onePassSignature.verify(signature)) {
            	keyGenHelper.writeMessage("Primljena poruka od:"+publicKey.getUserIDs().next());
            }
            else
            {
            	keyGenHelper.writeMessage("Verifikacija potpisa neuspesna");
            	return;
            }
            
            OutputStream outputStream = new FileOutputStream(targetFilePath);
        	outputStream.write(outputBytes);
		}
		else
		{
			PGPLiteralData literalData = (PGPLiteralData) o;
			byte[] bytesToWrite = new byte[maxByteSize];
			bytesToWrite = literalData.getInputStream().readAllBytes();
			
			OutputStream outputStream = new FileOutputStream(targetFilePath);
        	outputStream.write(bytesToWrite);
		}
	}
}
