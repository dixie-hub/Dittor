package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class CredentialReplyMsg extends ProtoMessage {
    public static final short MSG_ID = 202;

    private final int caID;
    private final GroupElement signatureShare;

    public CredentialReplyMsg(int caID, GroupElement signatureShare) {
        super(MSG_ID);
        this.caID = caID;
        this.signatureShare = signatureShare;
    }

    public int getCAID(){
        return caID;
    }


    public GroupElement getSignatureShare() {
        return signatureShare;
    }
    
    public static ISerializer<CredentialReplyMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<CredentialReplyMsg>() {
            @Override
            public void serialize(CredentialReplyMsg msg, ByteBuf out) {
                out.writeInt(msg.getCAID());

                JSONConverter jsonConverter = new JSONConverter();
                String shareStr = jsonConverter.serialize(msg.getSignatureShare().getRepresentation());

                byte[] bytes = shareStr.getBytes(StandardCharsets.UTF_8);
                out.writeInt(bytes.length);
                out.writeBytes(bytes);
            }

            @Override
            public CredentialReplyMsg deserialize(ByteBuf in) {
                System.out.println("[DEBUG-SERIALIZER] Incoming bytes detected for CredentialReplyMsg...");
                int caID = in.readInt();

                int len = in.readInt();
                byte[] bytes = new byte[len];
                in.readBytes(bytes);
                String shareStr = new String(bytes, StandardCharsets.UTF_8);

                JSONConverter jsonConverter = new JSONConverter();
                GroupElement share = pairing.getG1().restoreElement(jsonConverter.deserialize(shareStr));

                return new CredentialReplyMsg(caID, share);
            }
        };
    }
}
