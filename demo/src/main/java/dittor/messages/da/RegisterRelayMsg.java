package dittor.messages.da;

import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.List;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.VRFResult;
import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.network.ISerializer;

public class RegisterRelayMsg extends ProtoMessage {
    public static final short MSG_ID = 103;

    private final GroupElement userPublicKeyG2;
    private final VRFResult vrfData;
    private final Proof identityProof;
    private final String context;

    private final String nodeId;
    private final List<String> familyIds;

    public RegisterRelayMsg(GroupElement pubKey, VRFResult vrfData, Proof identityProof, String context, String nodeId, List<String> familyIds) {
        super(MSG_ID);
        this.userPublicKeyG2 = pubKey;
        this.vrfData = vrfData;
        this.identityProof = identityProof;
        this.context = context;

        this.nodeId = nodeId;
        this.familyIds = familyIds;
    }

    public GroupElement getUserPubKeyG2() {
        return userPublicKeyG2;
    }

    public VRFResult getVrfData() {
        return vrfData;
    }

    public Proof getIdentityProof() {
        return identityProof;
    }

    public String getContext() {
        return context;
    }

    public String getNodeId() {
        return nodeId;
    }

    public List<String> getFamilyIds() {
        return familyIds;
    }

    public static ISerializer<RegisterRelayMsg> serializer(BilinearGroup pairing) {
        return new ISerializer<RegisterRelayMsg>() {
            @Override
            public void serialize(RegisterRelayMsg msg, ByteBuf out) {
                JSONConverter jsonConverter = new JSONConverter();

                String pkStr = jsonConverter.serialize(msg.userPublicKeyG2.getRepresentation());
                String nymStr = jsonConverter.serialize(msg.vrfData.getPseudonym().getRepresentation());
                String zkpStr = jsonConverter.serialize(msg.vrfData.getZeroKnowledgeProof().getRepresentation());
                String proofChallengeStr = jsonConverter
                        .serialize(msg.identityProof.getChallenge().getRepresentation());
                String proofResponseStr = jsonConverter.serialize(msg.identityProof.getResponse().getRepresentation());

                byte[] contextBytes = msg.getContext().getBytes(StandardCharsets.UTF_8);
                out.writeInt(contextBytes.length);
                out.writeBytes(contextBytes);

                writeString(out, pkStr);
                writeString(out, nymStr);
                writeString(out, zkpStr);
                writeString(out, proofChallengeStr);
                writeString(out, proofResponseStr);

                writeString(out, msg.nodeId);
                out.writeInt(msg.familyIds.size());
                for (String familyId : msg.familyIds)
                    writeString(out, familyId);
            }

            @Override
            public RegisterRelayMsg deserialize(ByteBuf in) {
                JSONConverter jsonConverter = new JSONConverter();

                int contextLen = in.readInt();
                byte[] contextBytes = new byte[contextLen];
                in.readBytes(contextBytes);
                String context = new String(contextBytes, StandardCharsets.UTF_8);

                String pkStr = readString(in);
                String nymStr = readString(in);
                String zkpStr = readString(in);
                String proofChallengeStr = readString(in);
                String proofResponseStr = readString(in);

                String nodeId = readString(in);
                int familyIdsCount = in.readInt();
                List<String> familyIds = new ArrayList<>();
                for (int i = 0; i < familyIdsCount; i++) {
                    familyIds.add(readString(in));
                }

                try {
                    GroupElement pk = pairing.getG2().restoreElement(jsonConverter.deserialize(pkStr));
                    GroupElement nym = pairing.getGT().restoreElement(jsonConverter.deserialize(nymStr));
                    GroupElement zkp = pairing.getG1().restoreElement(jsonConverter.deserialize(zkpStr));

                    Zn zn = pairing.getZn();
                    Zn.ZnElement challenge = zn.restoreElement(jsonConverter.deserialize(proofChallengeStr));
                    Zn.ZnElement response = zn.restoreElement(jsonConverter.deserialize(proofResponseStr));

                    VRFResult vrfData = new VRFResult(nym, zkp);
                    Proof identityProof = new Proof(challenge, response);

                    return new RegisterRelayMsg(pk, vrfData, identityProof, context, nodeId, familyIds);
                } catch (Exception e) {
                    System.out.println("Error: ");
                    e.printStackTrace();
                    throw new RuntimeException("Failed to decode message components.");
                }
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
