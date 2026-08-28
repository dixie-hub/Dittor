package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class MasterPubKeyReplyMsg extends ProtoMessage {
    public static final short MSG_ID = 215;

    private final GroupElement mpkG1;
    private final GroupElement mpkG2;

    public MasterPubKeyReplyMsg(GroupElement mpkG1, GroupElement mpkG2) {
        super(MSG_ID);
        this.mpkG1 = mpkG1;
        this.mpkG2 = mpkG2;
    }

    public GroupElement getMpkG1() {
        return mpkG1;
    }

    public GroupElement getMpkG2() {
        return mpkG2;
    }

    public static ISerializer <MasterPubKeyReplyMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<MasterPubKeyReplyMsg>() {
            @Override
            public void serialize(MasterPubKeyReplyMsg msg, ByteBuf out) {
                JSONConverter jsonConverter = new JSONConverter();
                writeString(out, jsonConverter.serialize(msg.mpkG1.getRepresentation()));
                writeString(out, jsonConverter.serialize(msg.mpkG2.getRepresentation()));
            }

            @Override
            public MasterPubKeyReplyMsg deserialize(ByteBuf in) {
                JSONConverter jsonConverter = new JSONConverter();
                GroupElement mpkG1 = pairing.getG1().restoreElement(jsonConverter.deserialize(readString(in)));
                GroupElement mpkG2 = pairing.getG2().restoreElement(jsonConverter.deserialize(readString(in)));
                return new MasterPubKeyReplyMsg(mpkG1, mpkG2);
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
