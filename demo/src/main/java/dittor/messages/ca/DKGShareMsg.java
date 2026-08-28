package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class DKGShareMsg extends ProtoMessage {
    public static final short MSG_ID = 212;

    private final int senderId;
    private final Zn.ZnElement secretShare; // s_ij = f_i(j)
    private final Zn.ZnElement blindingShare; // t_ij = f'_i(j)

    public DKGShareMsg(int senderId, Zn.ZnElement secretShare, Zn.ZnElement blindingShare) {
        super(MSG_ID);
        this.senderId = senderId;
        this.secretShare = secretShare;
        this.blindingShare = blindingShare;
    }

    public int getSenderID() {
        return senderId;
    }

    public Zn.ZnElement getSecretShare() {
        return secretShare;
    }

    public Zn.ZnElement getBlindingShare() {
        return blindingShare;
    }

    public static ISerializer <DKGShareMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<DKGShareMsg>() {
            @Override
            public void serialize(DKGShareMsg msg, ByteBuf out) {
                JSONConverter jsonConverter = new JSONConverter();
                out.writeInt(msg.senderId);
                writeString(out, jsonConverter.serialize(msg.secretShare.getRepresentation()));
                writeString(out, jsonConverter.serialize(msg.blindingShare.getRepresentation()));
            }

            @Override
            public DKGShareMsg deserialize(ByteBuf in) {
                JSONConverter jsonConverter = new JSONConverter();
                int senderId = in.readInt();
                Zn zn = pairing.getZn();
                Zn.ZnElement secretShare = zn.restoreElement(jsonConverter.deserialize(readString(in)));
                Zn.ZnElement blindingShare = zn.restoreElement(jsonConverter.deserialize(readString(in)));
                return new DKGShareMsg(senderId, secretShare, blindingShare);
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
