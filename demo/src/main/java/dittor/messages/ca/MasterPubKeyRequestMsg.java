package dittor.messages.ca;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class MasterPubKeyRequestMsg extends ProtoMessage {
    public static final short MSG_ID = 214;

    public MasterPubKeyRequestMsg() {
        super(MSG_ID);
    }

    public static ISerializer<MasterPubKeyRequestMsg> serializer() {
        return new ISerializer<MasterPubKeyRequestMsg>() {
            @Override
            public void serialize(MasterPubKeyRequestMsg msg, ByteBuf out) {}

            @Override
            public MasterPubKeyRequestMsg deserialize(ByteBuf in) {
                return new MasterPubKeyRequestMsg();
            }
        };
    }
    
}
