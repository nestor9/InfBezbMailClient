package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import signature.SignatureManager;
import signature.SignatureManagerSignedObject;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEYSTORE ="./data/userb.jks";
	private static final String PASSWORD = "userb";
	private static final String ALIAS = "userb";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();


	private static SignatureManager signatureManager = new SignatureManager();
	private static SignatureManagerSignedObject signatureManagerSignedObject = new SignatureManagerSignedObject();

	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher desCipherEnc = Cipher.getInstance("DESede/CBC/PKCS5Padding");
           // KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			//SecretKey secretKey = keyGen.generateKey();
			//Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = desCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = desCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			KeyStore ks = keyStoreReader.readKeyStore(KEYSTORE, PASSWORD.toCharArray());
			Certificate cer = keyStoreReader.getCertificateFromKeyStore(ks, ALIAS);
			PublicKey pk = cer.getPublicKey();
			System.out.println(cer);
			System.out.println(pk);
			
			
			
			Cipher cipherenc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipherenc.init(Cipher.ENCRYPT_MODE, pk);
			
			
			
			byte[] encriptKey = cipherenc.doFinal(secretKey.getEncoded());
			//pocetak digitalnog potpisivanja
			System.out.println( "Digitalno potpisivanje");
			
			KeyPair keyPair = signatureManager.generateKeys();
			
			// preuzimamo javni kljuc
			PublicKey publicKey = keyPair.getPublic();
			
			// preuzimamo privatni kljuc
			PrivateKey privateKey = keyPair.getPrivate();
			
			Signature signing = Signature.getInstance("SHA256withRSA");
			signing.initSign(privateKey);
			signing.update(ciphertext);
			byte[] signature = signing.sign();
			
			
			System.out.println("Digital signature: " + new String (signature, "UTF-8"));
			

			MailBody mb = new MailBody(ciphertext, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), encriptKey,signature);
			System.out.println("nn");
			System.out.println(secretKey);
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr , mb.toCSV());
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	

        	
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	
	}
	
}
