package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class DKGCommitmentHashMsg extends ProtoMessage {
    public static final short MSG_ID = 210;

    private final int senderID;
    private final String commitmentHash;

    public DKGCommitmentHashMsg(int senderID, String commitmentHash) {
        super(MSG_ID);
        this.senderID = senderID;
        this.commitmentHash = commitmentHash;
    }

    public int getSenderID() {
        return senderID;
    }

    public String getCommitmentHash() {
        return commitmentHash;
    }

    public static ISerializer<DKGCommitmentHashMsg> serializer() {
        return new ISerializer<DKGCommitmentHashMsg>() {
            @Override
            public void serialize(DKGCommitmentHashMsg msg, ByteBuf out) {
                out.writeInt(msg.senderID);
                writeString(out, msg.commitmentHash);
            }

            @Override
            public DKGCommitmentHashMsg deserialize(ByteBuf in) {
                int senderID = in.readInt();
                String hash = readString(in);
                return new DKGCommitmentHashMsg(senderID, hash);
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
