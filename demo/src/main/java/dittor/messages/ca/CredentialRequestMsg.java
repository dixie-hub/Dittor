package dittor.messages.ca;

import java.nio.charset.StandardCharsets;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class CredentialRequestMsg extends ProtoMessage {
    public static final short MSG_ID = 201;

    private final GroupElement blindedCommitment;

    public CredentialRequestMsg(GroupElement blindedCommitment) {
        super(MSG_ID);
        this.blindedCommitment = blindedCommitment;
    }

    public GroupElement getBlindedCommitment() {
        return blindedCommitment;
    }

    public static ISerializer<CredentialRequestMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<CredentialRequestMsg>() {
            @Override
            public void serialize(CredentialRequestMsg msg, ByteBuf out) {
                JSONConverter jsonConverter = new JSONConverter();
                String commitmentStr = jsonConverter.serialize(msg.getBlindedCommitment().getRepresentation());

                byte[] bytes = commitmentStr.getBytes(StandardCharsets.UTF_8);
                out.writeInt(bytes.length);
                out.writeBytes(bytes);
            }

            @Override
            public CredentialRequestMsg deserialize(ByteBuf in) {
                int len = in.readInt();
                byte[] bytes = new byte[len];
                in.readBytes(bytes);
                String commitmentStr = new String(bytes, StandardCharsets.UTF_8);

                JSONConverter jsonConverter = new JSONConverter();
                GroupElement commitment = pairing.getG1().restoreElement(jsonConverter.deserialize(commitmentStr));

                return new CredentialRequestMsg(commitment);
            }
        };
    }
    
}
