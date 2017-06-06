//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java General
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
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
//import sun.security.x509.*;

public class ChatServer {

	private Hashtable _clientsRoomA;
    private Hashtable _clientsRoomB;
    private int _clientID = 0;
    private int _port;
    private String _hostName = null;
    // Some hints: security related fields.
    private String SERVER_KEYSTORE = "serverKeys";
    private char[] SERVER_KEYSTORE_PASSWORD = "123456".toCharArray();
    private char[] SERVER_KEY_PASSWORD = "123456".toCharArray();
    private ServerSocket _serverSocket = null;
    private SecureRandom secureRandom;
    private KeyStore serverKeyStore;
	private KeyPair pair;
	private PrivateKey priv;
    private PublicKey pub;
    private String roomKeyTempA = "01234567890123456789012345678901";
    private String roomKeyTempB = "23456789010134456789718345979902";
    String roomName = null;
    private String[][] clients = new String[3][2];
    public ChatServer(int port) throws NoSuchAlgorithmException, IOException {

    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        priv = pair.getPrivate();
        pub = pair.getPublic();
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("serverPublicKey");
        keyfos.write(key);
        keyfos.close();
        /*
         * 3 user signed for testing the authentication.
         */
        clients[0][0] = "cs470";//username
    	clients[0][1] = "16d505c9fe7b44442f7635e822e3ec4a4bfa0764"; // password : 123456
    	clients[1][0] = "cs471"; //username
    	clients[1][1] = "bd4e79a9098c6ebee22e564fcd27a1fefd6a321c"; // password : 654321
    	clients[2][0] = "cs472";//username
    	clients[2][1] = "64066c77b51e38777a90ef1786a681af2882b051"; // password : 012345
        try {
        	_clientsRoomA = new Hashtable();
            _clientsRoomB = new Hashtable();
            _serverSocket = null;
            _clientID = -1;
            _port = port;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();
        } catch (UnknownHostException e) {

            _hostName = "0.0.0.0";

        } catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    public static void main(String args[]) {

        try {
        	
            if (args.length != 1) {

                //  Might need more arguments if extending for extra credit
                System.out.println("Usage: java ChatServer portNum");
                return;

            } else {

                int port = Integer.parseInt(args[0]);
                ChatServer server = new ChatServer(port);
                server.run();
            }

        } catch (NumberFormatException e) {

            System.out.println("Useage: java ChatServer host portNum");
            e.printStackTrace();
            return;

        } catch (Exception e) {

            System.out.println("ChatServer error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /***
     *
     * Your methods for setting up secure connection
     *
     */
    public void run() {

        try {
        	
            _serverSocket = new ServerSocket(_port);
            System.out.println("ChatServer is running on "
                    + _hostName + " port " + _port);
           
          //Server'a baglanmak isteyen clientin ID'si ve o ID'ye atadigimiz random sayiyi tutuyoruz.
            String clientID = "";
            int nonce = 0;
            int temp = 0;
            while (true) {

                Socket socket = _serverSocket.accept();
                PrintWriter _out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader _in = new BufferedReader(
                        new InputStreamReader(
                                socket.getInputStream()));
                
                //round1: Takes the clientID from hello message and if that user exists, generate a nonce.
                String line = _in.readLine();
                clientID = line;
                System.out.println("The User Who Wants to Connect : "+clientID);
                if(!getPass(clientID).equals("Wrong Entry")){
	                Random randomGenerator = new Random();
	                nonce = randomGenerator.nextInt(65536);
	                _out.println(nonce);
	                temp++;
                }
                else{
                	_out.println("Wrong Entry");
                    socket.close();
                    continue;
                }

                /*round2: RSA decryption. Get the last character that suppose to be desired room.
                *Get the hash value before room.(As clientSide)
                *Calculate hash for the same value. If results are same add user to desired chat room.
                */
                line = _in.readLine();
                if (temp == 1 && line != null) {
                    String decrypted = RSA.decryptWithPrivate(line, priv);
                    if (decrypted.length() == 41) {
                    	char roomX = decrypted.charAt(40);
                        String clientSide = decrypted.substring(0, 40);
                        
                        //Get the users password which stored in server.
                        String sPass = getPass(clientID);
                        String serverSide = Crypto.sha1(Crypto.xor(sPass, nonce + ""));
                        
                        if (clientSide.equals(serverSide) && roomX == 'A' ) {

                            roomName = ""+roomX;
                        	String encryptedRoomKey = Crypto.encrypt(roomKeyTempA, serverSide.substring(0, 32));
                            ClientRecord clientRecord = new ClientRecord(socket);
                            _clientsRoomA.put(new Integer(_clientID++), clientRecord);
                            _out.println(encryptedRoomKey);
                            ChatServerThread thread = new ChatServerThread(this, socket);
                            clientID = "";
                            temp = 0;
                            thread.start();
                        }else if(clientSide.equals(serverSide) &&  roomX == 'B' ) {

                        	roomName = ""+roomX;
                        	String encryptedRoomKey = Crypto.encrypt(roomKeyTempB, serverSide.substring(0, 32));
                             ClientRecord clientRecord = new ClientRecord(socket);
                             _clientsRoomB.put(new Integer(_clientID++), clientRecord);
                             _out.println(encryptedRoomKey);
                             ChatServerThread thread = new ChatServerThread(this, socket);
                             clientID = "";
                             temp = 0;
                             thread.start();
                        }else{
                            _out.println("ERROR");
                            socket.close();
                            continue;
                        }
                    }
                
                
            
            }

            //_serverSocket.close();
            }
        } catch (IOException e) {

            System.err.println("Could not listen on port: " + _port);
            System.exit(-1);

        } catch (Exception e) {

            e.printStackTrace();
            System.exit(1);

        }
    }
    
    
    
	public String getRoomKeyTempA() {
		return roomKeyTempA;
	}

	public String getRoomKeyTempB() {
		return roomKeyTempB;
	}


	public PrivateKey getPrivateKey() {
		return pair.getPrivate();
	}

	public PublicKey getPublicKey() {
		return pair.getPublic();
	}
	
	public Hashtable getClientRecordsA() {
        return _clientsRoomA;
    }

    public Hashtable getClientRecordsB() {
        return _clientsRoomB;
    }
    
    public String getPass(String ID){
    	for(int i = 0; i<clients.length;i++){
	    	if(clients[i][0].equals(ID))
	    		return clients[i][1];
    	}
    	return "Wrong Entry";
    }    
}
