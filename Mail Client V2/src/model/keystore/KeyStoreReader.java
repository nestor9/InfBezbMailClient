package model.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreReader {

	public KeyStore readKeyStore(String keyStoreFilePath, char[] password) {
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance("JKS", "SUN");
			
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFilePath));
			keyStore.load(in, password);
		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			System.err.println("\n[KeyStoreReader - readKeyStore] Greska prilikom ucitavanja KeyStore-a. Proveriti da li je putanja ispravna i da li je prosledjen dobra sifra za otvaranje KeyStore-a!\n");			
		}
		
		return keyStore;
	}
	
	public Certificate getCertificateFromKeyStore(KeyStore keyStore, String alias) {
		Certificate certificate = null;
		try {
			certificate = keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		if (certificate == null) {
			System.err.println("\n[KeyStoreReader - getCertificateFromKeyStore] Sertifikat je null. Proveriti da li je alias ispravan!\n");
		}
		
		return certificate;
	}
	
	public PrivateKey getPrivateKeyFromKeyStore(KeyStore keyStore, String alias, char[] keyPass) {
		PrivateKey privateKey = null;
		try {
			privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		if (privateKey == null) {
			System.err.println("\n[KeyStoreReader - getPrivateKeyFromKeyStore] Privatni kljuc je null. Proveriti da li su ispravni alias i sifra za privatni kljuc!\n");
		}
		
		return privateKey;
	}
	
	public PublicKey getPublicKeyFromCertificate(Certificate certificate) {
		return certificate.getPublicKey();
	}
	
}
