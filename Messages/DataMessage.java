package Messages;

public class DataMessage extends Messages.Message {

    public DataMessage(byte[] data ) {
        //key message has packetType of 2
        super(2, data);
    }
}
