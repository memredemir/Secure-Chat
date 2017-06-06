package Chat;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Crypto {
	private static byte[] iv = {0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d};
	
	/**
	 * Encrypt method for distribution of room key.
	 * @param plaintext
	 * @param key
	 * @return
	 * @throws Exception
	 */
 
	public static String encrypt(String plaintext, String key) throws Exception {
        byte[] decodedKey = key.getBytes("UTF-8");
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, originalKey, ips);
        byte[] encryptedMessage = cipher.doFinal(plaintext.getBytes("ISO-8859-1"));
        return Base64.getEncoder().encodeToString(encryptedMessage);

    }
	/**
	 * Decrypt method for distribution of room key.
	 * @param ciphertext
	 * @param key
	 * @return
	 * @throws Exception
	 */
    public static String decrypt(String ciphertext, String key) throws Exception {
        byte[] decodedKey = key.getBytes("UTF-8");
        byte[] encryptedTextBytes = Base64.getDecoder().decode(ciphertext);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, originalKey, ips);
        return new String(cipher.doFinal(encryptedTextBytes), "ISO-8859-1");

    }
    
    /**
     * Hashing method in login protocol.
     * @param input
     * @return
     * @throws NoSuchAlgorithmException
     */
      
	public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

	/**
	 * Xor method in login protocol.
	 * @param s
	 * @param key
	 * @return
	 */
	 
	 public static String xor(String s, String key) {
	        StringBuilder sb = new StringBuilder();
	        for (int i = 0; i < s.length(); i++) {
	            sb.append((char) (s.charAt(i) ^ key.charAt(i % key.length())));
	        }
	        String result = sb.toString();
	        return result;
	    }
	 /**
	  *  Symmetric AES encryption for client communication.
	  * @param key
	  * @param value
	  * @return
	  */
	  
	  public static String encryptSym(String key, String value) {
	        try {
	        	IvParameterSpec _iv = new IvParameterSpec(iv);
	            SecretKey originalKey = new SecretKeySpec(key.getBytes("UTF-8"), 0, key.getBytes("UTF-8").length, "AES");

	            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            cipher.init(Cipher.ENCRYPT_MODE, originalKey, _iv);

	            byte[] encrypted = cipher.doFinal(value.getBytes("UTF-8"));
	            

	            return Base64.getEncoder().encodeToString(encrypted);
	        } catch (Exception ex) {
	            ex.printStackTrace();
	        }

	        return null;
	    }
	  
	  /** 
	   * Symmetric AES decryption for client communication.
	   * @param key
	   * @param encrypted
	   * @return
	   */
	   
	    public String decryptSym(String key, String encrypted) {
	        try {
	            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
	            IvParameterSpec _iv = new IvParameterSpec(iv);
	            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            byte[] encryptedTextBytes = Base64.getDecoder().decode(encrypted);
	            SecretKey originalKey = new SecretKeySpec(key.getBytes("UTF-8"), 0, key.getBytes("UTF-8").length, "AES");
	            cipher.init(Cipher.DECRYPT_MODE, originalKey, _iv);
	            return new String(cipher.doFinal(encryptedTextBytes), "UTF-8");
	        } catch (Exception ex) {
	            ex.printStackTrace();
	        }

	        return null;
	    }
	    
	    /**
	     * Hmac calculation method with SHA-1 algorithm.
	     * 
	     * @param data
	     * @param key
	     * @return
	     * @throws SignatureException
	     * @throws NoSuchAlgorithmException
	     * @throws InvalidKeyException
	     * @throws UnsupportedEncodingException
	     * @throws IllegalStateException
	     */
	    public static String calculateHMAC(String data, String key)
	            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalStateException {
	        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
	        Mac mac = Mac.getInstance("HmacSHA1");
	        mac.init(signingKey);
	        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
	    }
	
}
