package Node;

import static Utility.HashAndEncrypt.debug;
import static org.kohsuke.args4j.OptionHandlerFilter.ALL;
import Messages.DataMessage;
import Messages.HashedPacket;
import Messages.KeyMessage;
import Utility.HashAndEncrypt;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Client {

    @Option(name = "-p", usage = "port to connect to")
    private int portnumber = 9090;
    @Option(name = "-t", usage = "ip or hostname to connect to", required = true)
    private InetAddress serverIPAddress;
    @Option(name = "-k", usage = "passphrase, must match server", required = true)
    private String passphrase;

    public static void main(String[] args) throws IOException, CmdLineException {
        new Client().doMain(args);
    }

    private BigInteger DHKey;
    private byte[] key = new byte[32];

    public void doMain(String[] args) throws IOException {
        //parse args, print options, requirements, and an example if the user messes up
        CmdLineParser parser = new CmdLineParser(this);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            System.err.println("java Node.Client [options...]");
            parser.printUsage(System.err);
            System.err.println();
            System.err.println("  Example: java Node.Client" + parser.printExample(ALL));
            return;
        }

        //create connection to server
        Socket socket = new Socket(serverIPAddress, portnumber);

        //Initialize Bouncy Castle as security provider for client
        HashAndEncrypt.addSecurityProviderBC();
        OutputStream out = socket.getOutputStream();

        //Setup initial shared key
        try {
            DHKey = HashAndEncrypt.clientDHKeyExchange(socket);
            key = HashAndEncrypt.SaltandHashSHA256toKey(passphrase, DHKey);
            debug(new String(key));
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed key exchange");
            System.exit(1);
        }

        //Enter send message loop
        Scanner scanner = new Scanner(System.in);
        boolean sessionActive = true;
        while (sessionActive = true) {
            System.out.println("Please enter command: (SEND * | REKEY)");
            String message = null;
            try {
                message = scanner.nextLine();
            } catch (NoSuchElementException e) {
                System.out.println("User interrupt detected, halted.");
                System.exit(0);
            }
            if ( message.length() >= 4 && message.substring(0,4).toUpperCase().equals("SEND")) {
                HashedPacket packet = new HashedPacket(new DataMessage(message.substring(4).getBytes()), key);
                processMessage(packet, out);
            } else if ( message.length() >= 5 &&message.substring(0,5).toUpperCase().equals("REKEY")) {
                HashedPacket packet = new HashedPacket(new KeyMessage(), key);
                processMessage(packet, out);
                try {
                    DHKey = HashAndEncrypt.clientDHKeyExchange(socket);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                key = HashAndEncrypt.SaltandHashSHA256toKey(passphrase, DHKey);
            } else {
                System.err.println("Command not recognized, try again.");
            }
        }
        out.close();
    }

    public void processMessage(HashedPacket packet, OutputStream out) throws IOException {
        byte[] encryptedBytes = null;
        try {
            encryptedBytes = (packet.getEncryptedBytes(key));
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
        out.write(encryptedBytes.length);
        out.write(encryptedBytes);
        out.flush();
        System.out.println("Message sent");
    }
}