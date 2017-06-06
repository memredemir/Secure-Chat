//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java
import java.util.*;

import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;


// Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;
//import sun.misc.BASE64Encoder;

import Chat.ClientRecord;

public class ChatServerThread extends Thread {


    private Socket _socket = null;
    private ChatServer _server = null;
    private Hashtable _recordsA = null;
    private Hashtable _recordsB = null;
    private String pass = "123456";
    private byte[] _key = "1234567890123456\n".getBytes();
    private Crypto crypto;
    Hashtable send;
    ClientRecord clientRecord;
    String keyA;
    String keyB;
    public ChatServerThread(ChatServer server, Socket socket) {
    	
        super("ChatServerThread");
        _server = server;
        _socket = socket;
        _recordsA = server.getClientRecordsA();
        _recordsB = server.getClientRecordsB();
        send = new Hashtable();
        clientRecord = new ClientRecord(socket);
        crypto = new Crypto();
        keyA = server.getRoomKeyTempA();
        keyB = server.getRoomKeyTempB();
    }

    public void run() {

        try {
        	
            BufferedReader _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));
            
            String msg;
              
            
            /*
             * If received message is not null. Check the users room and send the message to users in that room.
             */
            while ((msg = _in.readLine()) != null) {
            	
            	if (whereIsRecord(clientRecord)=='A') {
                    send = _recordsA;

                } else {
                    send = _recordsB;

                }
                Enumeration theClients = send.elements();

                while (theClients.hasMoreElements()) {
                	
                	try {
                        
                        ClientRecord c = (ClientRecord) theClients.nextElement();
                        int mac_length = 0;
                        Socket socket = c.getClientSocket();
                        PrintWriter _out = new PrintWriter(socket.getOutputStream(), true);

                    		_out.println(msg);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                    

                }
            }

            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        } catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }
    
    // Look where is the record that sends the message.
    public char whereIsRecord(ClientRecord clientRecord) {
        Enumeration theClients = _recordsA.elements();
        while (theClients.hasMoreElements()) {
            ClientRecord c = (ClientRecord) theClients.nextElement();
            if (c.toString().equals(clientRecord.toString())) {
                return 'A';
            }
        }
        return 'B';
    }
    
    
    
}
