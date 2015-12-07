package Messages;

import org.bouncycastle.asn1.*;

abstract public class Message implements ASN1Encodable{

    int packetType;
    static int sequenceNumber = 0;
    byte [] data;

    public Message(int packetType, byte[] data ) {
        this.packetType = packetType;
        this.sequenceNumber +=1;
        this.data = data;
    }

    static public void newSequence(){
        sequenceNumber = 0;
    }

    @Override
    public String toString(){
        return new String(data);
    }

    public String toDebugString(){
        return "[" + packetType + ", " + sequenceNumber + ", " + new String(data) + "]";
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[] {new ASN1Integer(packetType), new ASN1Integer(sequenceNumber), new DERBitString(data)});
    }
}
