package dittor.protocols;

import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;

import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import dittor.crypto.DA;
import dittor.messages.da.RegisterRelayMsg;
import dittor.messages.da.RegisterRelayReplyMsg;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.network.data.Host;

public class DAProtocol extends GenericProtocol {
    public static final String PROTOCOL_NAME = "DAProtocol";
    public static final short PROTOCOL_ID = 102;

    private final BilinearGroup pairing;
    private final DA cryptoDA;
    private int channelID;

    public DAProtocol(BilinearGroup pairing, DA cryptoDA) {
        super(PROTOCOL_NAME, PROTOCOL_ID);
        this.pairing = pairing;
        this.cryptoDA = cryptoDA;
    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        Properties channelProps = new Properties();
        channelProps.setProperty(TCPChannel.ADDRESS_KEY, props.getProperty("address"));
        channelProps.setProperty(TCPChannel.PORT_KEY, props.getProperty("port"));
        this.channelID = createChannel(TCPChannel.NAME, channelProps);

        registerMessageSerializer(channelID, RegisterRelayMsg.MSG_ID, RegisterRelayMsg.serializer(pairing));
        registerMessageSerializer(channelID, RegisterRelayReplyMsg.MSG_ID, RegisterRelayReplyMsg.serializer());

        registerMessageHandler(channelID, RegisterRelayMsg.MSG_ID, this::handleRegisterRelay);
    }

    private void handleRegisterRelay(RegisterRelayMsg msg, Host from, short sourceProto, int channel) {
        System.out.println("[DA] Verifying Sybil defense tokens for incoming Relay registration...");

        boolean isVrfValid = cryptoDA.verifyVrf(msg.getUserPubKeyG2(), msg.getVrfData(), msg.getContext());
        boolean isCredentialValid = cryptoDA.verifyCredentialLinkage(msg.getUserPubKeyG2(),
                msg.getCredentialCommitmentG1(), msg.getCredential(), msg.getDLEQProof(), msg.getContext());

        RegisterRelayReplyMsg reply;
        if (isVrfValid && isCredentialValid) {
            boolean accepted = cryptoDA.registerNode(msg.getContext(), msg.getVrfData().getPseudonym(), msg.getNodeId(),
                    new HashSet<>(msg.getFamilyIds()));

            if (accepted) {
                System.out.println("[DA] Verification SUCCESS. Adding to Tor Consensus list.");
                reply = new RegisterRelayReplyMsg(true, "Authorized: Added to Tor relay consensus directory.");
            } else {
                System.err.println("[DA] Verification FAILURE. Pseudonym is being reused without a shared family!");
                reply = new RegisterRelayReplyMsg(false, "Unauthorized: pseudonym already claimed by another node.");
            }
        } else {
            System.err.println("[DA] Verification FAILURE. Credential linkage validation failed.");
            reply = new RegisterRelayReplyMsg(false, "Unauthorized: credential linkage validation failed.");
        }

        openConnection(from, channel);
        sendMessage(reply, sourceProto, from);
    }

}
