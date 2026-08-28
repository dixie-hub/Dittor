package dittor.protocols;

import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import dittor.messages.ca.MasterPubKeyReplyMsg;
import dittor.messages.ca.MasterPubKeyRequestMsg;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionUp;
import pt.unl.fct.di.novasys.network.data.Host;

// Protocolo para o arranque da Main, pergunta a mpk a uma CA já pronta
public class MasterPubKeyFetcher extends GenericProtocol {
    public static final String PROTOCOL_NAME = "MasterPubKeyFetcher";
    public static final short PROTOCOL_ID = 101;

    private final BilinearGroup pairing;
    private int channelID;
    private Host caHost;
    private short caProtoID;
    private final CompletableFuture<MasterPubKeyReplyMsg> result = new CompletableFuture<>();

    public MasterPubKeyFetcher(BilinearGroup pairing) {
        super(PROTOCOL_NAME, PROTOCOL_ID);
        this.pairing = pairing;
    }

    @Override
    public void init(Properties properties) throws HandlerRegistrationException, IOException {
        Properties channelProperties = new Properties();
        channelProperties.setProperty(TCPChannel.ADDRESS_KEY, properties.getProperty("address"));
        channelProperties.setProperty(TCPChannel.PORT_KEY, properties.getProperty("port"));
        this.channelID = createChannel(TCPChannel.NAME, channelProperties);

        registerChannelEventHandler(channelID, OutConnectionUp.EVENT_ID, this::onOutConnectionUp);

        registerMessageSerializer(channelID, MasterPubKeyRequestMsg.MSG_ID, MasterPubKeyRequestMsg.serializer());
        registerMessageSerializer(channelID, MasterPubKeyReplyMsg.MSG_ID, MasterPubKeyReplyMsg.serializer(pairing));

        registerMessageHandler(channelID, MasterPubKeyReplyMsg.MSG_ID, this::handleReply);
    }

    private void onOutConnectionUp(OutConnectionUp event, int channel) {
        sendMessage(new MasterPubKeyRequestMsg(), caProtoID, caHost);
    }

    private void handleReply(MasterPubKeyReplyMsg msg, Host from, short sourceProto, int channel) {
        result.complete(msg);
    }

    // bloqueia até receber a mpk de uma CA
    public GroupElement[] fetchBlocking(Host caHost, int caID, int maxAttempts, long attemptTimeoutMillis)
            throws Exception {
        this.caHost = caHost;
        this.caProtoID = (short) (CAProtocol.BASE_PROTOCOL_ID + caID);
        openConnection(caHost, channelID);

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                MasterPubKeyReplyMsg reply = result.get(attemptTimeoutMillis, TimeUnit.MILLISECONDS);
                return new GroupElement[] { reply.getMpkG1(), reply.getMpkG2() };
            } catch (TimeoutException e) {
                System.out.println("[MasterPubKeyFetcher] CA-" + caID + " not ready yet, retrying (" + attempt + "/" + maxAttempts + ")...");
                sendMessage(new MasterPubKeyRequestMsg(), caProtoID, caHost);
            }
        }
        throw new IllegalStateException("CA-" + caID + " did not respond with its master public key in time.");
    }
}
