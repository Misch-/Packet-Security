package Messages;

public class KeyMessage extends Messages.Message{

    public KeyMessage() {
        //key message has packetType of 1
        //key message has no payload, but puts client and
        // server thread into DH exchange mode and resets sequence
        super(1, new byte[]{(byte)0});
        Messages.Message.newSequence();
    }

    //Didn't put DH information in key message because parameters need to be send both ways anyway with pub keys.
}
