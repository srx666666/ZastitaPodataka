package etf.openpgp.da160086d;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.crypto.KeyGenerator;

import org.bouncycastle.*;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyGeneratorHelper {
	private PGPSecretKeyRingCollection privateSecrets;
	private PGPPublicKeyRingCollection publicSecrets;
	private String publicKeysPath, privateKeysPath;
	private static int keySizeAes = 128;
	private static int keySizeDes = 168;
	private GUIwindow mainGui;
	
	public KeyGeneratorHelper(String privatePath, String publicPath, GUIwindow gui) throws IOException, PGPException
	{
		publicSecrets = new PGPPublicKeyRingCollection(new ArrayList());
		privateSecrets = new PGPSecretKeyRingCollection(new ArrayList());
		File publicKeysFile = new File(publicPath);
		if (publicKeysFile.exists())
		{
			FileInputStream inputStream = new FileInputStream(publicKeysFile);
            publicSecrets = new PGPPublicKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
		}
		
		File privateKeysFile = new File(privatePath);
		if (privateKeysFile.exists())
		{
			FileInputStream inputStream = new FileInputStream(privateKeysFile);
            privateSecrets = new PGPSecretKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
		}
		
		publicKeysPath = publicPath;
		privateKeysPath = privatePath;
		mainGui = gui;
	}
	
	public void writeMessage(String message)
	{
		mainGui.writeMessage(message);
	}
	
	public PGPSecretKeyRingCollection GetPrivateSecrets()
	{
		return privateSecrets;
	}
	
	public PGPPublicKeyRingCollection GetPublicSecrets()
	{
		return publicSecrets;
	}
	
	public void GenerateRSA(String name, String mail, String password, int keySize) throws NoSuchAlgorithmException, PGPException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException
	{
		 KeyPairGenerator keyPairGeneratorRsa = KeyPairGenerator.getInstance("RSA");
		 keyPairGeneratorRsa.initialize(keySize);
		 KeyPair rsaKp = keyPairGeneratorRsa.generateKeyPair();
		 
		 KeyPairGenerator keyPairGeneratorDsa = KeyPairGenerator.getInstance("DSA");
		 keyPairGeneratorRsa.initialize(1024);
		 KeyPair dsaKp = keyPairGeneratorDsa.generateKeyPair();
		 
		 PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
		 PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date());
		 
		 PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
		 .build().get(HashAlgorithmTags.SHA1);
		 
		 PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
		 PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair, name+"#"+mail, sha1Calc, null, null,
		 new JcaPGPContentSignerBuilder(
		 dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
		 new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)
		 .setProvider("BC").build(password.toCharArray()));
		 
		 keyRingGen.addSubKey(rsaKeyPair);
		 
		 PGPSecretKeyRing privateKeyRing = keyRingGen.generateSecretKeyRing();
		 
		 this.AddAndSavePrivateSecrets(privateKeyRing);
		 
	}
	
	public void GenerateAES(String name, String mail) throws NoSuchAlgorithmException, IOException, PGPException
	{
		 KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		 keyGenerator.init(keySizeAes);
		 Key aesKey = keyGenerator.generateKey();
		 
		 PGPPublicKeyRing keyRing = new PGPPublicKeyRing(aesKey.getEncoded(), new JcaKeyFingerprintCalculator());
		 
		 this.AddAndSavePublicSecrets(keyRing);
	}
	
	public void GenerateDES(String name, String mail) throws NoSuchAlgorithmException, IOException, PGPException
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("TripleDES");
		keyGenerator.init(keySizeDes);
		Key desKey = keyGenerator.generateKey();
		 
		PGPPublicKeyRing keyRing = new PGPPublicKeyRing(desKey.getEncoded(), new JcaKeyFingerprintCalculator());
		 
		this.AddAndSavePublicSecrets(keyRing);
	}
	
	public void AddAndSavePrivateSecrets(PGPSecretKeyRing keyRing) throws IOException
	{
		if (keyRing != null)
			privateSecrets = PGPSecretKeyRingCollection.addSecretKeyRing(privateSecrets, keyRing);
		
		OutputStream outputStream = new FileOutputStream(privateKeysPath);
		BufferedOutputStream secretOut = new BufferedOutputStream(outputStream);
		privateSecrets.encode(secretOut);
		secretOut.close();
	}
	
	public void AddAndSavePublicSecrets(PGPPublicKeyRing keyRing) throws IOException
	{
		if (keyRing!=null)
			publicSecrets = PGPPublicKeyRingCollection.addPublicKeyRing(publicSecrets, keyRing);
		
		OutputStream outputStream = new FileOutputStream(publicKeysPath);
		BufferedOutputStream secretOut = new BufferedOutputStream(outputStream);
		publicSecrets.encode(secretOut);
		secretOut.close();
	}
	
	public PGPPublicKeyRing GetPublicKeyById(long id)
	{
		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = publicSecrets;
		
		java.util.Iterator<PGPPublicKeyRing> iter = pgpPublicKeyRingCollection.getKeyRings();
	    PGPPublicKeyRing keyRing;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        java.util.Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
	        // skip master key
	        //
	        PGPPublicKey publicKey = keyIter.next();
	        publicKey = keyIter.next();

	        long keyId  = publicKey.getKeyID();
	        if (keyId == id) 
	        {
	        	return keyRing;
	        }
	    }
	    PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = privateSecrets;
		
		java.util.Iterator<PGPSecretKeyRing> iter2 = pgpPrivateKeyRingCollection.getKeyRings();
	    PGPSecretKeyRing secretKeyRing;
	    while (iter2.hasNext()) 
	    {
	        secretKeyRing = iter2.next();
	        java.util.Iterator<PGPPublicKey> keyIter = secretKeyRing.getPublicKeys();
	        // skip master key
	        PGPPublicKey masterKey = keyIter.next();
	        PGPPublicKey publicKey = keyIter.next();

	        long keyId= publicKey.getKeyID();
	        
	        if (keyId == id) 
	        {
	        	List<PGPPublicKey> publicKeysList = new ArrayList<>();
	        	publicKeysList.add(masterKey);
	        	publicKeysList.add(publicKey);
	        	return new PGPPublicKeyRing(publicKeysList);
	        }
	    }
	    
	    return null;
	}
	
	public PGPSecretKeyRing GetPrivateKeyById(long id)
	{
		PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = privateSecrets;
		
		java.util.Iterator<PGPSecretKeyRing> iter = pgpPrivateKeyRingCollection.getKeyRings();
	    PGPSecretKeyRing keyRing;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        java.util.Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
	        // skip the master key
	        //
	        PGPSecretKey privateKey = keyIter.next();
	        privateKey = keyIter.next();

	        long keyId= privateKey.getKeyID();
	        
	        if (keyId == id) 
	        {
	        	return keyRing;
	        }
	    }
	    
	    return null;
	}
	
	public PGPPublicKeyRing GetPublicKeyByPosition(int pos)
	{
		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = publicSecrets;
		
		java.util.Iterator<PGPPublicKeyRing> iter = pgpPublicKeyRingCollection.getKeyRings();
	    PGPPublicKeyRing keyRing;
	    
	    int curNumber = 0;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        if (curNumber == pos) 
	        {
	        	return keyRing;
	        }
	        curNumber++;
	    }
	    
	    return null;
	}
	
	public void DeleteSecretKeyPair(long id) throws PGPException
	{
		PGPSecretKeyRing keyRing = privateSecrets.getSecretKeyRing(id);
		privateSecrets = privateSecrets.removeSecretKeyRing(privateSecrets, keyRing);
		
		try {
			AddAndSavePrivateSecrets(null);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void DeletePublicKey(long id) throws PGPException
	{
		PGPPublicKeyRing keyRing = publicSecrets.getPublicKeyRing(id);
		publicSecrets = publicSecrets.removePublicKeyRing(publicSecrets, keyRing);
		
		try {
			AddAndSavePublicSecrets(null);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public PGPSecretKeyRing GetPrivateKeyByPosition(int pos)
	{
		PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = privateSecrets;
		
		java.util.Iterator<PGPSecretKeyRing> iter = pgpPrivateKeyRingCollection.getKeyRings();
	    PGPSecretKeyRing keyRing;
	    
	    int curNumber = 0;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        if (curNumber == pos) 
	        {
	        	return keyRing;
	        }
	        curNumber++;
	    }
	    
	    return null;
	}
	
	public PGPPublicKeyRing GetPublicMasterKeyById(long id)
	{
		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = publicSecrets;
		
		java.util.Iterator<PGPPublicKeyRing> iter = pgpPublicKeyRingCollection.getKeyRings();
	    PGPPublicKeyRing keyRing;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        java.util.Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
	        // skip master key
	        //
	        PGPPublicKey publicKey = keyIter.next();

	        long keyId  = publicKey.getKeyID();
	        if (keyId == id) 
	        {
	        	return keyRing;
	        }
	    }
	    PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = privateSecrets;
		
		java.util.Iterator<PGPSecretKeyRing> iter2 = pgpPrivateKeyRingCollection.getKeyRings();
	    PGPSecretKeyRing secretKeyRing;
	    while (iter2.hasNext()) 
	    {
	        secretKeyRing = iter2.next();
	        java.util.Iterator<PGPPublicKey> keyIter = secretKeyRing.getPublicKeys();
	        // skip master key
	        PGPPublicKey publicKey = keyIter.next();

	        long keyId= publicKey.getKeyID();
	        
	        if (keyId == id) 
	        {
	        	List<PGPPublicKey> publicKeysList = new ArrayList<>();
	        	publicKeysList.add(publicKey);
	        	return new PGPPublicKeyRing(publicKeysList);
	        }
	    }
	    
	    return null;
	}
	
	public PGPSecretKeyRing GetPrivateMasterKeyById(long id)
	{
		PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = privateSecrets;
		
		java.util.Iterator<PGPSecretKeyRing> iter = pgpPrivateKeyRingCollection.getKeyRings();
	    PGPSecretKeyRing keyRing;
	    while (iter.hasNext()) 
	    {
	        keyRing = iter.next();
	        java.util.Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
	        // skip the master key
	        //
	        PGPSecretKey privateKey = keyIter.next();

	        long keyId= privateKey.getKeyID();
	        
	        if (keyId == id) 
	        {
	        	return keyRing;
	        }
	    }
	    
	    return null;
	}
}
