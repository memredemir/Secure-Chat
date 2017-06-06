package Chat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class RSA {
    /**
     * Encryption method with public key.
     * @param msg
     * @return
     * @throws Exception
     */
    public static String encryptWithPublic(String msg) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Path path = Paths.get("serverPublicKey");
        byte[] pubBytes = Files.readAllBytes(path);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubBytes));
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal(msg.getBytes("ISO-8859-1"));
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }
    /**
     * Decryption method with private key.
     * @param encryptedText
     * @param priv
     * @return
     * @throws Exception
     */
    public static String decryptWithPrivate(String encryptedText, PrivateKey priv) throws Exception {
        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return new String(cipher.doFinal(encryptedTextBytes), "ISO-8859-1");
    }
    
}