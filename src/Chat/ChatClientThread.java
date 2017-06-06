/**
 *  Created 2/16/2003 by Ting Zhang 
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package Chat;

// socket
import java.math.BigInteger;

import java.net.*;
import java.io.*;

//  Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;
    private Crypto crypto;
    private String roomKey;
    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        crypto = new Crypto();
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
        
        roomKey = client.getRoomKey();
    }

    public void run() {

        try {
            BufferedReader _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));
            String msg;
            /* If received message is not null, get the mac length and mac value.
             * Calculate yourself a mac value for encrypted message.
             * If they are same send the message to Chat screen.
             */ 
            while ((msg = _in.readLine()) != null) {
            	int mac_length = Integer.parseInt(msg.substring(msg.length()-2));
            	String encryptedMsg = msg.substring(0,(msg.length()-mac_length)-2);
            	String hmac = msg.substring(encryptedMsg.length(),msg.length()-2);

            	String hmac1 = Crypto.calculateHMAC((Crypto.calculateHMAC( encryptedMsg, roomKey)), roomKey);
            	System.out.println("\nReceived Message : " + encryptedMsg 
            			+ "\nReceived HMAC : " + hmac1);
            	
            	if(hmac1.equals(hmac)){
            		System.out.println("Hashes are same");
            		msg = crypto.decryptSym(roomKey,encryptedMsg);
            		consumeMessage(msg + " \n");
            	}
            	
            }
            System.out.println("Server Closed...");
            _socket.close();

        } catch (IOException e) {
        	
            e.printStackTrace();
        } catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }

    public void consumeMessage(String msg) {


        if (msg != null) {
            _outputArea.append(msg);
        }

    }
}
