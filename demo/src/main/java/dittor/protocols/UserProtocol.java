package dittor.protocols;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import dittor.crypto.User;
import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.SchnorrZKP;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.VRFResult;
import dittor.messages.ca.CredentialReplyMsg;
import dittor.messages.ca.CredentialRequestMsg;
import dittor.messages.da.RegisterRelayMsg;
import dittor.messages.da.RegisterRelayReplyMsg;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionDown;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionFailed;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionUp;
import pt.unl.fct.di.novasys.network.data.Host;

public class UserProtocol extends GenericProtocol {
    public static final String PROTOCOL_NAME = "UserProtocol";
    public static final short PROTOCOL_ID = 100;

    private final BilinearGroup pairing;
    private final User cryptoUser;
    private final int threshold;

    private final DodisYampolskiyVRF vrf;
    private final SchnorrZKP schnorr;
    private final GroupElement baseG;
    private final GroupElement baseH;
    private final GroupElement mpkG1;
    private final GroupElement mpkG2;
    private final GroupElement g1;
    private final GroupElement g2;

    private int channelID;
    private Host daHost;
    private final Map<Host, Integer> caHostToIDMap;

    private GroupElement blindedCommitment;
    private final Map<Integer, GroupElement> receivedShares;
    private boolean thresholdReached = false;

    public UserProtocol(BilinearGroup pairing, User cryptoUser, int threshold, DodisYampolskiyVRF vrf, SchnorrZKP schnorr, GroupElement baseG, GroupElement baseH, GroupElement mpkG1, GroupElement mpkG2, GroupElement g1, GroupElement g2) {
        super(PROTOCOL_NAME, PROTOCOL_ID);
        this.pairing = pairing;
        this.cryptoUser = cryptoUser;
        this.threshold = threshold;
        this.vrf = vrf;
        this.schnorr = schnorr;
        this.baseG = baseG;
        this.baseH = baseH;
        this.mpkG1 = mpkG1;
        this.mpkG2 = mpkG2;
        this.g1 = g1;
        this.g2 = g2;
        this.receivedShares = new HashMap<>();
        this.caHostToIDMap = new HashMap<>();
    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        Properties channelProperties = new Properties();
        channelProperties.setProperty(TCPChannel.ADDRESS_KEY, props.getProperty("address"));
        channelProperties.setProperty(TCPChannel.PORT_KEY, props.getProperty("port"));
        this.channelID = createChannel(TCPChannel.NAME, channelProperties);

        registerChannelEventHandler(channelID, OutConnectionUp.EVENT_ID, this::onOutConnectionUp);
        registerChannelEventHandler(channelID, OutConnectionFailed.EVENT_ID, this::onOutConnectionFailed);
        registerChannelEventHandler(channelID, OutConnectionDown.EVENT_ID, this::onOutConnectionDown);
        
        registerMessageSerializer(channelID, CredentialRequestMsg.MSG_ID, CredentialRequestMsg.serializer(pairing));
        registerMessageSerializer(channelID, CredentialReplyMsg.MSG_ID, CredentialReplyMsg.serializer(pairing));
        registerMessageSerializer(channelID, RegisterRelayMsg.MSG_ID, RegisterRelayMsg.serializer(pairing));
        registerMessageSerializer(channelID, RegisterRelayReplyMsg.MSG_ID, RegisterRelayReplyMsg.serializer());

        registerMessageHandler(channelID, CredentialReplyMsg.MSG_ID, this::handleCredentialReply);
        registerMessageHandler(channelID, RegisterRelayReplyMsg.MSG_ID, this::handleRegisterRelayReply);
    }

    public void startRegistration(Map<Host, Integer> targetCAs, Host targetDA) {
        System.out.println("[User] Generating fresh blinded commitment primtive...");
        this.blindedCommitment = cryptoUser.createBlindedCommit(this.baseG, this.baseH);
        this.daHost = targetDA;
        this.caHostToIDMap.putAll(targetCAs);

        for (Host caHost : caHostToIDMap.keySet()) {
            System.out.println("[User] Opening channel connection to CA: " + caHost);
            openConnection(caHost, channelID);
        }
    }

    private void onOutConnectionUp(OutConnectionUp event, int channel) {
        Host target = event.getNode();
        System.out.println("[User] Connection successfully established with: " + target);

        if (target.equals(daHost)) {
            sendRegistrationToDA();
        } else if (caHostToIDMap.containsKey(target)) {
            int caID = caHostToIDMap.get(target);
            short destProto = (short) (200 + caID);

            System.out.println("[User] Dispatching CredentialRequestMsg to CA-" + caHostToIDMap.get(target));
            sendMessage(new CredentialRequestMsg(this.blindedCommitment), destProto, target);
        }
    }

    private void onOutConnectionFailed(OutConnectionFailed<?> event, int channel) {
        System.err.println("[User] CRITICAL: Connection attempt failed to target host: " + event.getNode());
    }

    private void onOutConnectionDown(OutConnectionDown event, int channel) {
        System.out.println("[User] Connection severed from host: " + event.getNode());
    }
    
    private void handleCredentialReply(CredentialReplyMsg msg, Host from, short sourceProto, int channel) {
        int incomingCaID = msg.getCAID();
        System.out.println("[User] Received valid signature share from CA ID: " + incomingCaID);

        receivedShares.put(incomingCaID, msg.getSignatureShare());

        if (receivedShares.size() >= threshold && !thresholdReached) {
            thresholdReached = true;
            System.out.println("[User] Threshold criteria satisfied (" + threshold + " shares collected). Unblinding tokens...");

            List<Integer> signerIDs = new ArrayList<>(receivedShares.keySet());
            List<GroupElement> sigShares = new ArrayList<>(receivedShares.values());

            GroupElement aggregatedBlindedSignature = cryptoUser.aggregateShares(sigShares, signerIDs);
            GroupElement unblindedSignature = cryptoUser.unblindSignature(aggregatedBlindedSignature, this.mpkG1);

            boolean localCheck = cryptoUser.verifyCredential(unblindedSignature, this.mpkG2, this.g1, this.g2);
            System.out.println("[User] Local signature validation diagnostic check: " + (localCheck ? "PASS" : "FAIL"));
            System.out.println("[User] Handshaking with Directory Authority Gatekeeper...");

            openConnection(daHost, channelID);
        }
    }

    private void sendRegistrationToDA() {
        System.out.println("[User] Formulating Zero-Knowledge Linkage Proof and VRF Token for DA consensus...");
        
        String context = "TorRelayConsensus2026";

        GroupElement userPubKey = cryptoUser.getPublicKeyG2();
        VRFResult vrfResult = cryptoUser.generateVRFPseudonym(this.vrf, context);
        Proof identityZKP = cryptoUser.generateSchnorrPoK(this.schnorr, context);

        System.out.println(pairing.getGT().getClass());

        RegisterRelayMsg registrationMsg = new RegisterRelayMsg(userPubKey, vrfResult, identityZKP, context);
        
        sendMessage(registrationMsg, DAProtocol.PROTOCOL_ID, daHost);
    }

    private void handleRegisterRelayReply(RegisterRelayReplyMsg msg, Host from, short sourceProto, int channel) {
        if (msg.isSuccess())
            System.out.println("Registration approved: " + msg.getStatusMessage());
        else
            System.err.println("Registration denied: " + msg.getStatusMessage());

        System.out.println("[User] Execution cycle complete.");
        //System.exit(0);
    }
}
