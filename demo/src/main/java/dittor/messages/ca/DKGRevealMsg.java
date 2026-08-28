package dittor.messages.ca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class DKGRevealMsg extends ProtoMessage {
    public static final short MSG_ID = 211;

    private final int senderID;
    private final List<GroupElement> commitmentsG1; // C_{i,k},k = 0...t-1
    private final GroupElement pubKeyG1; // h1^{a_0}
    private final GroupElement pubKeyG2; // g2^{a_0}

    public DKGRevealMsg(int senderID, List<GroupElement> commitmentsG1, GroupElement pubKeyG1, GroupElement pubKeyG2) {
        super(MSG_ID);
        this.senderID = senderID;
        this.commitmentsG1 = commitmentsG1;
        this.pubKeyG1 = pubKeyG1;
        this.pubKeyG2 = pubKeyG2;
    }

    public int getSenderID() {
        return senderID;
    }

    public List<GroupElement> getCommitmentsG1() {
        return commitmentsG1;
    }

    public GroupElement getPubKeyG1() {
        return pubKeyG1;
    }

    public GroupElement getPubKeyG2() {
        return pubKeyG2;
    }

    public static ISerializer<DKGRevealMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<DKGRevealMsg>() {
            @Override
            public void serialize(DKGRevealMsg msg, ByteBuf out) {
                JSONConverter jsonConverter = new JSONConverter();
                
                out.writeInt(msg.senderID);
                out.writeInt(msg.commitmentsG1.size());
                for (GroupElement c : msg.commitmentsG1) {
                    writeString(out, jsonConverter.serialize(c.getRepresentation()));
                }
                writeString(out, jsonConverter.serialize(msg.pubKeyG1.getRepresentation()));
                writeString(out, jsonConverter.serialize(msg.pubKeyG2.getRepresentation()));
            }

            @Override
            public DKGRevealMsg deserialize(ByteBuf in) {
                JSONConverter jsonConverter = new JSONConverter();

                int senderID = in.readInt();
                int count = in.readInt();
                List<GroupElement> commitments = new ArrayList<>();
                for (int i = 0; i < count; i++) {
                    commitments.add(pairing.getG1().restoreElement(jsonConverter.deserialize(readString(in))));
                }
                GroupElement pubKeyG1 = pairing.getG1().restoreElement(jsonConverter.deserialize(readString(in)));
                GroupElement pubKeyG2 = pairing.getG2().restoreElement(jsonConverter.deserialize(readString(in)));

                return new DKGRevealMsg(senderID, commitments, pubKeyG1, pubKeyG2);
            }

            private void writeString(ByteBuf out, String str) {
                byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
                out.writeInt(bytes.length);
                out.writeBytes(bytes);
            }

            private String readString(ByteBuf in) {
                int len = in.readInt();
                byte[] bytes = new byte[len];
                in.readBytes(bytes);
                return new String(bytes, StandardCharsets.UTF_8);
            }
        };
    }


}
