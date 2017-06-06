//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.
package Chat;

//  AWT/Swing
import java.awt.*;

import java.awt.event.*;
import javax.swing.*;

//  Java
import java.io.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.net.*;



//  Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Base64;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
public class ChatClient {

    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;
    String _loginName;
    ChatServer _server;
    ChatClientThread _thread;
    ChatLoginPanel _loginPanel;
    ChatRoomPanel _chatPanel;
    PrintWriter _out = null;
    BufferedReader _in = null;
    CardLayout _layout;
    JFrame _appFrame;
    private Crypto cryptography;
    Socket _socket = null;
    SecureRandom secureRandom;
    KeyStore clientKeyStore;
    KeyStore caKeyStore;
    private String roomKey;
  
    //  ChatClient Constructor
    //
    //  empty, as you can see.
    public ChatClient() {
    	
        _loginName = null;
        _server = null;
        cryptography = new Crypto();
        try {
			
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        try {
            initComponents();
        } catch (Exception e) {
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "Login");

    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);

    }

    //  main
    //
    //  Construct the app inside a frame, in the center of the screen
    public static void main(String[] args) {
        
        ChatClient app = new ChatClient();

        app.run();
    }

    //  initComponents
    //
    //  Component initialization
    private void initComponents() throws Exception {

        _appFrame = new JFrame("Chat Project");
        _layout = new CardLayout();
        _appFrame.getContentPane().setLayout(_layout);
        _loginPanel = new ChatLoginPanel(this);
        _chatPanel = new ChatRoomPanel(this);
        _appFrame.getContentPane().add(_loginPanel, "Login");
        _appFrame.getContentPane().add(_chatPanel, "ChatRoom");
        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownOutput();
            _thread.join();
            _socket.close();
            
        } catch (Exception err) {
            System.out.println("ChatClient error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  connect
    //
    //  Called from the login panel when the user clicks the "connect"
    //  button. You will need to modify this method to add certificate
    //  authentication.  
    //  There are two passwords : the keystorepassword is the password
    //  to access your private key on the file system
    //  The other is your authentication password on the CA.
    //
    public int connect(String loginName, char[] password,
            String keyStoreName, char[] keyStorePassword,
            String serverHost, int serverPort,String roomX) {

        try {
        	
            _loginName = loginName;
            _socket = new Socket(serverHost, serverPort);
            _out = new PrintWriter(_socket.getOutputStream(), true);
            _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));
            
            
            //round1: sends loginName as hello message.
            _out.println(loginName);
            
            /*round2: temp = 0, received nonce value, hash that value 2^16 times and xor with password.
            * Add the room that desired to enter at the end of this xor value.(A or B)  
            * Then encrypt them with servers RSA public key.(As temp key, we will use that to get the real room key.)
            */
            String line = "";
            int nonce = 0;
            boolean connected = false;
            String tempKey = "";  
            int temp = 0;
            while (!connected) {
            	if ( temp ==0 && (line = _in.readLine()) != null) {
            		if(line.equals("Wrong Entry")){
            			_socket.close();
                        System.out.println("Wrong Entry");
                        return 0;
            		}
                    nonce = Integer.parseInt(line);
                    System.out.println(nonce);
                    String str = String.valueOf(password);
                    
                    for (int i = 0; i < 15; i++) {
                        str = Crypto.sha1(str);
                    }
                    
                    tempKey = Crypto.sha1(Crypto.xor(str, nonce + ""));
                    
                    String encrypted = RSA.encryptWithPublic(tempKey+roomX);
                    _out.println(encrypted);
                    
                    temp++;
            	}
            	
            	//round3: Symmetric AES decryption with temp key to get the room key.  
            	else if (temp == 1 && (line = _in.readLine()) != null) {
                    if (line.equals("ERROR")) {
                        _socket.close();
                        System.out.println("Wrong Entry");
                        return 1;
                    }
                    roomKey = new String(Crypto.decrypt(line, tempKey.substring(0, 32)));

                    connected = true;
                    temp = 0;
                }
            	
            	
            	
            }
            
            _layout.show(_appFrame.getContentPane(), "ChatRoom");
            
            _thread = new ChatClientThread(this);
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println("Don't know about the serverHost: " + serverHost);
            System.exit(1);

        } catch (IOException e) {

            System.err.println("Couldn't get I/O for "
                    + "the connection to the serverHost: " + serverHost);
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();

            System.exit(1);

        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

        return ERROR;

    }

    /* sendMessage
     * Hmac calculation with SHA-1 and encryption/decryption with AES.
     * Put the mac length at the end of the message we want to send.
     * Called from the ChatPanel when the user types a carrige return.
     */
    public void sendMessage(String msg) {

        try {
            msg = _loginName + "> " + msg;
            
            msg = cryptography.encryptSym(roomKey, msg);
//			SecretKeySpec secretKey = new SecretKeySpec(roomKey.getBytes(), "HmacSHA1");
			           
			String mac = cryptography.calculateHMAC(cryptography.calculateHMAC(msg, roomKey),roomKey);
			msg += mac;
			msg += mac.length();
            _out.println(msg);

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

    }
	
    
    public Socket getSocket() {

        return _socket;
    }

    public JTextArea getOutputArea() {

        return _chatPanel.getOutputArea();
    }
    
    public String getRoomKey() {
        return roomKey;
    }
    
}
