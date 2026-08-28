package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class DKGComplaintMsg extends ProtoMessage {
    public static final short MSG_ID = 213;

    private final int senderId;
    private final int accusedId;
    private final String reason;

    public DKGComplaintMsg(int senderId, int accusedId, String reason) {
        super(MSG_ID);
        this.senderId = senderId;
        this.accusedId = accusedId;
        this.reason = reason;
    }

    public int getSenderID() {
        return senderId;
    }

    public int getAccusedId() {
        return accusedId;
    }

    public String getReason() {
        return reason;
    }

    public static ISerializer<DKGComplaintMsg> serializer() {
        return new ISerializer<DKGComplaintMsg>() {
            @Override
            public void serialize(DKGComplaintMsg msg, ByteBuf out) {
                out.writeInt(msg.senderId);
                out.writeInt(msg.accusedId);
                writeString(out, msg.reason);
            }

            @Override
            public DKGComplaintMsg deserialize(ByteBuf in) {
                int senderId = in.readInt();
                int accusedId = in.readInt();
                String reason = readString(in);
                return new DKGComplaintMsg(senderId, accusedId, reason);
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
