package Node;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

import Utility.HashAndEncrypt;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.InvalidCipherTextException;

import static Utility.HashAndEncrypt.debug;


public class ServerThread extends Thread {

    private Socket socket;
    private SocketAddress clientAddress;
    private String passphrase;

    private BigInteger DHKey;
    private byte[] key = new byte[32];

    public ServerThread(Socket socket, SocketAddress address, String passphrase) {
        super("Node.ServerThread");
        this.socket = socket;
        this.clientAddress = address;
        this.passphrase = passphrase;
        try {
            DHKey = HashAndEncrypt.serverDHKeyExchange(socket);
            key = HashAndEncrypt.SaltandHashSHA256toKey(passphrase, DHKey);
            debug(new String(key));
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed key exchange");
            System.exit(1);
        }
    }

    public void run() {
        //Enter receive message loop
        try {
            InputStream in = socket.getInputStream();
            System.out.println("Client " + clientAddress + " has connected.");
            int size;
            boolean sessionActive = true;
            while (sessionActive = true && !socket.isClosed()) {
                size = in.read();
                System.out.println(size + " bytes received from " + clientAddress);
                byte [] byteStream = new byte[size];
                in.read(byteStream, 0, size);
                debug("Message in is: " + new String(byteStream));
                byteStream = HashAndEncrypt.decryptCBCAES256(byteStream, key);
                debug("Message out is: " + new String(byteStream));
                DLSequence dlSequence = (DLSequence)ASN1Primitive.fromByteArray(byteStream);
                //Copys from the end of derSequence to the end of the message to extract the hash
                byte[] hash = Arrays.copyOfRange(byteStream, dlSequence.getEncoded().length, byteStream.length);
                //If packetType is 1, detect rekey
                if (((ASN1Integer)dlSequence.toArray()[0]).getValue().equals(BigInteger.ONE)){
                    DHKey = HashAndEncrypt.serverDHKeyExchange(socket);
                    key = HashAndEncrypt.SaltandHashSHA256toKey(passphrase, DHKey);
                } else {
                    System.out.println("Client has sent message #" + ((ASN1Integer) dlSequence.toArray()[1]).getValue() + " which includes the following message and hash,");
                    System.out.println("Message: " + new String(((DERBitString) dlSequence.toArray()[2]).getBytes()));
                    System.out.println("Hash: " + DatatypeConverter.printHexBinary(hash));
                    System.out.println();
                }
            }
            in.close();
            System.out.println("Client " + clientAddress + " has disconnected.");
        } catch (SocketException e) {
            System.out.println("Client " + clientAddress + " has disconnected.");
        } catch (IOException e) {
            System.err.println("I/O Exception, Error receiving data.");
            e.printStackTrace();
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}