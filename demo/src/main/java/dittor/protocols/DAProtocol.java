package dittor.protocols;

import java.io.IOException;
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
        boolean isZkpValid = cryptoDA.verifyIdentityProof(msg.getUserPubKeyG2(), msg.getIdentityProof(), msg.getContext());

        RegisterRelayReplyMsg reply;
        if (isVrfValid && isZkpValid) {
            System.out.println("[DA] Verification SUCCESS. Adding to Tor consensus list.");
            reply = new RegisterRelayReplyMsg(true, "Authorized: Added to Tor relay consensus directory.");
        } else {
            System.err.println("[DA] Verification FAILURE. Sybil signature validation failed.");
            reply = new RegisterRelayReplyMsg(false, "Unauthorized: ZKP identity link validation failed."); 
        }

        openConnection(from, channel);
        sendMessage(reply, sourceProto, from);
    }
    
}
