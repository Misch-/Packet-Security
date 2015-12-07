package Messages;

import Utility.HashAndEncrypt;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;

import static Utility.HashAndEncrypt.debug;

public class HashedPacket {

    private int size; //in bytes
    private byte[] encodedMessageBytes;
    private byte[] hashBytes;


    public HashedPacket(Message message, byte[] key) throws IOException {
        this.encodedMessageBytes = message.toASN1Primitive().getEncoded("DER");
        this.hashBytes = HashAndEncrypt.hashHMACSHA256(encodedMessageBytes, key);
        this.size = encodedMessageBytes.length + hashBytes.length;
    }

    public int getSize(){
        return size;
    }

    public byte[] getEncodedMessageBytes(){
        return encodedMessageBytes;
    }

    public byte[] getHashBytes(){
        return hashBytes;
    }

    public byte[] getEncryptedBytes(byte[] key) throws InvalidCipherTextException {

        //Merges byte arrays into one array for encryption
        byte[] encryptBytes = new byte[encodedMessageBytes.length + hashBytes.length];
        System.arraycopy(encodedMessageBytes, 0, encryptBytes, 0, encodedMessageBytes.length);
        System.arraycopy(hashBytes, 0, encryptBytes, encodedMessageBytes.length, hashBytes.length);
        //Overwrite unencrypted buffer with encrypted bytes and return it
        debug("Message in is: " + new String(encryptBytes));
        encryptBytes = Utility.HashAndEncrypt.encryptCBCAES256(encryptBytes, key);
        debug("Message out is: " + new String(encryptBytes));
        return encryptBytes;
    }
}
