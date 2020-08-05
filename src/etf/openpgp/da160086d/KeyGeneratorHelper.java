package etf.openpgp.da160086d;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.crypto.KeyGenerator;

import org.bouncycastle.*;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
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
	
	public KeyGeneratorHelper(String publicPath, String privatePath) throws IOException, PGPException
	{
		publicSecrets = new PGPPublicKeyRingCollection(null);
		privateSecrets = new PGPSecretKeyRingCollection(null);
		publicKeysPath = publicPath;
		privateKeysPath = privatePath;
	}
	
	public void GenerateRSA(String name, String mail, String password, int keySize) throws NoSuchAlgorithmException, PGPException, KeyStoreException, CertificateException, IOException
	{
		 KeyPairGenerator keyPairGeneratorRsa = KeyPairGenerator.getInstance("RSA");
		 keyPairGeneratorRsa.initialize(keySize);
		 KeyPair rsaKp = keyPairGeneratorRsa.generateKeyPair();
		 
		 KeyPairGenerator keyPairGeneratorDsa = KeyPairGenerator.getInstance("DSA");
		 keyPairGeneratorDsa.initialize(keySizeDes);
		 KeyPair dsaKp = keyPairGeneratorDsa.generateKeyPair();
		 
		 PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
		 PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date());
		 
		 PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
		 .build().get(HashAlgorithmTags.SHA1);
		 
		 PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
		 PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair, name, sha1Calc, null, null,
		 new JcaPGPContentSignerBuilder(
		 dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384),
		 new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)
		 .setProvider("BCFIPS").build(password.toCharArray()));
		 
		 PGPSecretKeyRing privateKeyRing = keyRingGen.generateSecretKeyRing();
		 PGPPublicKeyRing publicKeyRing = keyRingGen.generatePublicKeyRing();
		 
		 PGPSecretKeyRing.insertSecretKey(privateKeyRing, (PGPSecretKey) rsaKp.getPrivate());
		 PGPPublicKeyRing.insertPublicKey(publicKeyRing, (PGPPublicKey) rsaKp.getPublic());
		 
		 this.AddAndSavePublicSecrets(publicKeyRing);
		 
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
		PGPSecretKeyRingCollection.addSecretKeyRing(privateSecrets, keyRing);
		
		ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
		privateSecrets.encode(secretOut);
		secretOut.close();
		
		File secretsFile = new File(privateKeysPath);
		if (secretsFile.exists())
			secretsFile.delete();
		
		try(OutputStream outputStream = new FileOutputStream(privateKeysPath)) {
		    secretOut.writeTo(outputStream);
		}
	}
	
	public void AddAndSavePublicSecrets(PGPPublicKeyRing keyRing) throws IOException
	{
		PGPPublicKeyRingCollection.addPublicKeyRing(publicSecrets, keyRing);
		
		ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
		publicSecrets.encode(secretOut);
		secretOut.close();
		
		File secretsFile = new File(publicKeysPath);
		if (secretsFile.exists())
			secretsFile.delete();
		
		try(OutputStream outputStream = new FileOutputStream(publicKeysPath)) {
		    secretOut.writeTo(outputStream);
		}
	}
	
}
