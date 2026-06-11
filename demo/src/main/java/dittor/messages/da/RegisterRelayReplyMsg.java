package dittor.messages.da;

import java.nio.charset.StandardCharsets;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class RegisterRelayReplyMsg extends ProtoMessage {
    public static final short MSG_ID = 104;

    private final boolean success;
    private final String statusMessage;
    
    public RegisterRelayReplyMsg(boolean success, String statusMessage) {
        super(MSG_ID);
        this.success = success;
        this.statusMessage = statusMessage;
    }

    public boolean isSuccess() { return success; }
    public String getStatusMessage() { return statusMessage; }

    public static ISerializer<RegisterRelayReplyMsg> serializer() {
        return new ISerializer<RegisterRelayReplyMsg>() {
            @Override
            public void serialize(RegisterRelayReplyMsg msg, ByteBuf out) {
                out.writeBoolean(msg.success);

                byte[] msgBytes = msg.statusMessage.getBytes(StandardCharsets.UTF_8);
                out.writeInt(msgBytes.length);
                out.writeBytes(msgBytes);
            }

            @Override
            public RegisterRelayReplyMsg deserialize(ByteBuf in) {
                boolean success = in.readBoolean();

                int len = in.readInt();
                byte[] msgBytes = new byte[len];
                in.readBytes(msgBytes);
                String statusMessage = new String(msgBytes, StandardCharsets.UTF_8);

                return new RegisterRelayReplyMsg(success, statusMessage);
            }
        };
    }
    
}
