package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient{

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEYSTORE = "./data/userb.jks";
	private static  final String PASSWORD = "userb";
	private static final String ALIAS = "userb";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";

	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        } 
      
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
			MimeMessage chosenMessage = mimeMessages.get(answer);
	   
			MailBody mb = new MailBody(MailHelper.getText(chosenMessage));
			
			byte [] iv1 = mb.getIV1Bytes();
			IvParameterSpec vector1 = new IvParameterSpec(iv1);
			byte [] iv2 = mb.getIV2Bytes();
			IvParameterSpec vector2 = new IvParameterSpec(iv2);
			byte [] body = mb.getEncMessageBytes();
			byte [] encSessionKey = mb.getEncKeyBytes();	
			String encMessage = mb.getEncMessage();

		
			KeyStore ks = keyStoreReader.readKeyStore(KEYSTORE, PASSWORD.toCharArray());
			PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(ks, ALIAS, PASSWORD.toCharArray());
			
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] secretKey = rsaCipher.doFinal(encSessionKey);
			SecretKey ss = new SecretKeySpec(secretKey, "DESede");
			//SecretKey ss = new SecretKeySpec(secretKey, "AES");
			
			
			Cipher bodyCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			//Cipher bodyCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			bodyCipher.init(Cipher.DECRYPT_MODE, ss, vector1);
			byte[] text = bodyCipher.doFinal(body);
			
			String receivedBodyTxt = new String(bodyCipher.doFinal(Base64.decode(encMessage)));
			String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
			
			bodyCipher.init(Cipher.DECRYPT_MODE, ss, vector2);

			//bodyCipher.init(Cipher.DECRYPT_MODE, ss, vector2);
			//byte [] decoded = Base64.decode(chosenMessage.getSubject());
			//String decryptedSubject = new String(bodyCipher.doFinal(decoded));
			
			String decryptedSubjectTxt = new String(bodyCipher.doFinal(Base64.decode(chosenMessage.getSubject())));
			String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
			
			System.out.println("Body: " + decompressedBodyText);
			System.out.println("Subject: " + new String(decompressedSubjectTxt));
			System.out.println("Bez dekompresije: " + new String(text));
			}
	
}
