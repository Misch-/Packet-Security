package Node;

import static org.kohsuke.args4j.OptionHandlerFilter.ALL;

import Utility.HashAndEncrypt;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    @Option(name = "-p", usage = "port to listen on")
    private int portnumber = 9090;
    @Option(name = "-k", usage = "passphrase, client must match server", required = true)
    private String passphrase;

    public static void main(String[] args) throws IOException, CmdLineException {
        new Server().doMain(args);
    }

    public void doMain(String[] args) throws IOException {
        //parse args, print options, requirements, and an example if the user messes up
        CmdLineParser parser = new CmdLineParser(this);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            System.err.println("java Node.Server [options...]");
            parser.printUsage(System.err);
            System.err.println();
            System.err.println("  Example: java Node.Server" + parser.printExample(ALL));
            return;
        }
        //have to initialize socket or compiler complains
        ServerSocket server = null;
        //start listening for clients on the port
        try {
            server = new ServerSocket(portnumber);
            System.out.println("Started Node.Server Listening to Port: " + portnumber);
        } catch (IOException e) {
            System.err.println("Could not listen on port: " + portnumber);
            System.exit(-1);
        }
        //Initialize Bouncy Castle as security provider for server
        HashAndEncrypt.addSecurityProviderBC();
        //when a client is found, spin up a serverThread for them on another socket,
        //also passes the pass phrase to the thread
        boolean serverRunning = true;

        while (serverRunning) {
            Socket acceptedSocket = server.accept();
            new ServerThread(acceptedSocket, acceptedSocket.getRemoteSocketAddress(), passphrase).start();
        }
        server.close();
    }
}
