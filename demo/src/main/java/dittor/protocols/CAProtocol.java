package dittor.protocols;

import java.io.IOException;
import java.util.Properties;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import dittor.crypto.CA;
import dittor.messages.ca.CredentialReplyMsg;
import dittor.messages.ca.CredentialRequestMsg;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.channel.tcp.events.InConnectionDown;
import pt.unl.fct.di.novasys.channel.tcp.events.InConnectionUp;
import pt.unl.fct.di.novasys.network.data.Host;

public class CAProtocol extends GenericProtocol {
    public static final String BASE_PROTOCOL_NAME = "CAProtocol";
    public static final short BASE_PROTOCOL_ID = 200;

    private final BilinearGroup pairing;
    private final CA cryptoCA;
    private final int caID;
    private int channelID;

    public CAProtocol(BilinearGroup pairing, CA cryptoCA, int caID) {
        super(BASE_PROTOCOL_NAME + "-" + caID, (short) (BASE_PROTOCOL_ID + caID));
        this.pairing = pairing;
        this.cryptoCA = cryptoCA;
        this.caID = caID;
    } 

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        Properties channelProps = new Properties();
        channelProps.setProperty(TCPChannel.ADDRESS_KEY, props.getProperty("address"));
        channelProps.setProperty(TCPChannel.PORT_KEY, props.getProperty("port"));
        this.channelID = createChannel(TCPChannel.NAME, channelProps);

        registerChannelEventHandler(channelID, InConnectionUp.EVENT_ID, this::onInConnectionUp);
        registerChannelEventHandler(channelID, InConnectionDown.EVENT_ID, this::onInConnectionDown);

        registerMessageSerializer(channelID, CredentialRequestMsg.MSG_ID, CredentialRequestMsg.serializer(pairing));
        registerMessageSerializer(channelID, CredentialReplyMsg.MSG_ID, CredentialReplyMsg.serializer(pairing));
        
        registerMessageHandler(channelID, CredentialRequestMsg.MSG_ID, this::handleCredentialRequest);
    }

    private void onInConnectionUp(InConnectionUp event, int channel) {
        System.out.println("[CA-" + caID + "] User connection open from: " + event.getNode());
    }

    private void onInConnectionDown(InConnectionDown event, int channel) {
        System.out.println("[CA-" + caID + "] User connection closed: " + event.getNode());
    }

    private void handleCredentialRequest(CredentialRequestMsg msg, Host from, short sourceProto, int channel) {
        System.out.println("[CA-" + caID + "] Processing Blind Commitment from " + from);

        GroupElement signatureShare = cryptoCA.issueSignatureShare(msg.getBlindedCommitment());

        CredentialReplyMsg reply = new CredentialReplyMsg(this.caID, signatureShare);

        System.out.println("[CA-" + caID + "] Opening outbound reply channel back to: " + from);
        openConnection(from, channelID);

        System.out.println("[CA-" + caID + "] Dispatching partial share back to " + from);
        sendMessage(reply, sourceProto, from);
    }
    
}
