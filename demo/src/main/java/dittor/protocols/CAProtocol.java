package dittor.protocols;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import dittor.crypto.CA;
import dittor.messages.ca.CredentialReplyMsg;
import dittor.messages.ca.CredentialRequestMsg;
import dittor.messages.ca.DKGCommitmentHashMsg;
import dittor.messages.ca.DKGComplaintMsg;
import dittor.messages.ca.DKGRevealMsg;
import dittor.messages.ca.DKGShareMsg;
import dittor.messages.ca.MasterPubKeyReplyMsg;
import dittor.messages.ca.MasterPubKeyRequestMsg;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.channel.tcp.events.InConnectionDown;
import pt.unl.fct.di.novasys.channel.tcp.events.InConnectionUp;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionFailed;
import pt.unl.fct.di.novasys.channel.tcp.events.OutConnectionUp;
import pt.unl.fct.di.novasys.network.data.Host;

public class CAProtocol extends GenericProtocol {
    public static final String BASE_PROTOCOL_NAME = "CAProtocol";
    public static final short BASE_PROTOCOL_ID = 200;

    private enum DkgState {
        AWAITING_HASHES, AWAITING_REVEALS, AWAITING_SHARES, DONE
    };

    private final BilinearGroup pairing;
    private final CA cryptoCA;
    private final int caID;
    private final GroupElement g1;
    private final GroupElement h1;
    private final GroupElement g2;
    private int channelID;

    private Map<Host, Integer> hostToPeerId;
    private int threshold;
    private int n;

    private DkgState state = DkgState.AWAITING_HASHES;
    private String myCommitmentHash;

    private final Set<Integer> connectedPeerIds = new HashSet<>();
    private final Map<Integer, String> receivedHashes = new HashMap<>();
    private final Set<Integer> disqualifiedIds = new HashSet<>();
    private final Map<Integer, List<GroupElement>> receivedCommitments = new HashMap<>();
    private final Map<Integer, GroupElement> receivedPubKeyG1 = new HashMap<>();
    private final Map<Integer, GroupElement> receivedPubKeyG2 = new HashMap<>();
    private final Map<Integer, Zn.ZnElement> receivedSecretShares = new HashMap<>();

    public CAProtocol(BilinearGroup pairing, CA cryptoCA, int caID, GroupElement g1, GroupElement h1, GroupElement g2) {
        super(BASE_PROTOCOL_NAME + "-" + caID, (short) (BASE_PROTOCOL_ID + caID));
        this.pairing = pairing;
        this.cryptoCA = cryptoCA;
        this.caID = caID;
        this.g1 = g1;
        this.h1 = h1;
        this.g2 = g2;
    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        Properties channelProps = new Properties();
        channelProps.setProperty(TCPChannel.ADDRESS_KEY, props.getProperty("address"));
        channelProps.setProperty(TCPChannel.PORT_KEY, props.getProperty("port"));
        this.channelID = createChannel(TCPChannel.NAME, channelProps);

        registerChannelEventHandler(channelID, InConnectionUp.EVENT_ID, this::onInConnectionUp);
        registerChannelEventHandler(channelID, InConnectionDown.EVENT_ID, this::onInConnectionDown);
        registerChannelEventHandler(channelID, OutConnectionUp.EVENT_ID, this::onOutConnectionUp);
        registerChannelEventHandler(channelID, OutConnectionFailed.EVENT_ID, this::onOutConnectionFailed);

        registerMessageSerializer(channelID, CredentialRequestMsg.MSG_ID, CredentialRequestMsg.serializer(pairing));
        registerMessageSerializer(channelID, CredentialReplyMsg.MSG_ID, CredentialReplyMsg.serializer(pairing));
        registerMessageSerializer(channelID, DKGCommitmentHashMsg.MSG_ID, DKGCommitmentHashMsg.serializer());
        registerMessageSerializer(channelID, DKGRevealMsg.MSG_ID, DKGRevealMsg.serializer(pairing));
        registerMessageSerializer(channelID, DKGShareMsg.MSG_ID, DKGShareMsg.serializer(pairing));
        registerMessageSerializer(channelID, DKGComplaintMsg.MSG_ID, DKGComplaintMsg.serializer());
        registerMessageSerializer(channelID, MasterPubKeyRequestMsg.MSG_ID, MasterPubKeyRequestMsg.serializer());
        registerMessageSerializer(channelID, MasterPubKeyReplyMsg.MSG_ID, MasterPubKeyReplyMsg.serializer(pairing));

        registerMessageHandler(channelID, CredentialRequestMsg.MSG_ID, this::handleCredentialRequest);
        registerMessageHandler(channelID, DKGCommitmentHashMsg.MSG_ID, this::handleCommitmentHash);
        registerMessageHandler(channelID, DKGRevealMsg.MSG_ID, this::handleReveal);
        registerMessageHandler(channelID, DKGShareMsg.MSG_ID, this::handleShare);
        registerMessageHandler(channelID, DKGComplaintMsg.MSG_ID, this::handleComplaint);
        registerMessageHandler(channelID, MasterPubKeyRequestMsg.MSG_ID, this::handleMasterPubKeyRequest);
    }

    // chamado pela CA depois do init()
    public void startDKG(Map<Host, Integer> peerHosts, int threshold, int n) {
        this.hostToPeerId = peerHosts;
        this.threshold = threshold;
        this.n = n;

        cryptoCA.generatePrivatePolynomial(threshold);
        cryptoCA.computeCommitments(g1, h1, g2);
        this.myCommitmentHash = cryptoCA.getCommitmentHash();
        this.receivedHashes.put(caID, myCommitmentHash);

        System.out.println("[CA-" + caID + "] Starting DKG, connecting to " + peerHosts.size() + " peer CAs...");
        for (Host peerHost : peerHosts.keySet()) {
            openConnection(peerHost, channelID);
        }

        checkHashPhaseComplete();
    }

    private void onInConnectionUp(InConnectionUp event, int channel) {
        System.out.println("[CA-" + caID + "] Incoming connection open from: " + event.getNode());
    }

    private void onInConnectionDown(InConnectionDown event, int channel) {
        System.out.println("[CA-" + caID + "] Incoming connection closed: " + event.getNode());
    }

    private void onOutConnectionUp(OutConnectionUp event, int channel) {
        Host target = event.getNode();

        Integer peerId = null;
        if (hostToPeerId != null)
            peerId = hostToPeerId.get(target);
        if (peerId == null)
            return;

        System.out.println("[CA-" + caID + "] Connected to CA-" + peerId + " for DKG!");
        short peerProto = (short) (BASE_PROTOCOL_ID + peerId);
        sendMessage(new DKGCommitmentHashMsg(caID, myCommitmentHash), peerProto, target);
        connectedPeerIds.add(peerId);

        if (state != DkgState.AWAITING_HASHES) {
            // ligação tardia da CA, como os hashes já foram revelados reenviamos
            sendMessage(new DKGRevealMsg(caID, cryptoCA.getRevealedCommitments(), cryptoCA.getRevealedPubKeyG1(),
                    cryptoCA.getRevealedPubKeyG2()), peerProto, target);
        } else {
            checkHashPhaseComplete();
        }
    }

    private void onOutConnectionFailed(OutConnectionFailed<?> event, int channel) {
        Host target = event.getNode();
        
        Integer peerId = null;
        if (hostToPeerId != null) {
            peerId = hostToPeerId.get(target);
        }
        if (peerId == null) return;

        System.out.println("[CA-" + caID + "] Connection to CA-" + peerId + " failed, retrying in two seconds...");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {}
        openConnection(target, channelID);
    }

    private void handleCommitmentHash(DKGCommitmentHashMsg msg, Host from, short sourceProto, int channel) {
        receivedHashes.put(msg.getSenderID(), msg.getCommitmentHash());
        if (state == DkgState.AWAITING_HASHES)
            checkHashPhaseComplete();
    }

    private void checkHashPhaseComplete() {
        if (state != DkgState.AWAITING_HASHES)
            return;
        if (hostToPeerId == null)
            return;
        if (receivedHashes.size() < n)
            return;
        if (connectedPeerIds.size() < hostToPeerId.size())
            return;

        System.out.println("[CA-" + caID + "] All " + n + " commitment hashes received. Revealing commitments...");
        state = DkgState.AWAITING_REVEALS;

        receivedCommitments.put(caID, cryptoCA.getRevealedCommitments());
        receivedPubKeyG1.put(caID, cryptoCA.getRevealedPubKeyG1());
        receivedPubKeyG2.put(caID, cryptoCA.getRevealedPubKeyG2());

        DKGRevealMsg reveal = new DKGRevealMsg(caID, cryptoCA.getRevealedCommitments(), cryptoCA.getRevealedPubKeyG1(),
                cryptoCA.getRevealedPubKeyG2());
        for (Map.Entry<Host, Integer> entry : hostToPeerId.entrySet()) {
            sendMessage(reveal, (short) (BASE_PROTOCOL_ID + entry.getValue()), entry.getKey());
        }

        checkRevealPhaseComplete();
    }

    private void handleReveal(DKGRevealMsg msg, Host from, short sourceProto, int channel) {
        int sender = msg.getSenderID();

        if (!receivedHashes.containsKey(sender)) {
            System.out.println(
                    "[CA-" + caID + "] CA-" + sender + " DISQUALIFIED: revealed before publishing commitment hash");
            disqualifiedIds.add(sender);
            broadcastComplaint(sender, "revealed before publishing commitment hash");
            checkRevealPhaseComplete();
            return;
        }

        String recomputed = CA.hashCommitments(msg.getCommitmentsG1(), msg.getPubKeyG1(), msg.getPubKeyG2());
        if (!recomputed.equals(receivedHashes.get(sender))) {
            System.out.println("[CA-" + caID + "] CA-" + sender
                    + " DISQUALIFIED: revealed commitments do not match published hash");
            disqualifiedIds.add(sender);
            broadcastComplaint(sender, "revealed commitments do not match published hash");
            checkRevealPhaseComplete();
            return;
        }

        receivedCommitments.put(sender, msg.getCommitmentsG1());
        receivedPubKeyG1.put(sender, msg.getPubKeyG1());
        receivedPubKeyG2.put(sender, msg.getPubKeyG2());

        if (state == DkgState.AWAITING_REVEALS)
            checkRevealPhaseComplete();
    }

    private void checkRevealPhaseComplete() {
        if (state != DkgState.AWAITING_REVEALS)
            return;

        Set<Integer> accounted = new HashSet<>(receivedCommitments.keySet());
        accounted.addAll(disqualifiedIds);
        if (accounted.size() < n)
            return;

        System.out.println("[CA-" + caID + "] All reveals accounted for. Distributing shares...");
        state = DkgState.AWAITING_SHARES;

        // partilha própria
        receivedSecretShares.put(caID, cryptoCA.evaluateSecretPolynomial(caID));

        for (Map.Entry<Host, Integer> entry : hostToPeerId.entrySet()) {
            int peerId = entry.getValue();
            if (disqualifiedIds.contains(peerId))
                continue;

            Zn.ZnElement s_ij = cryptoCA.evaluateSecretPolynomial(peerId);
            Zn.ZnElement t_ij = cryptoCA.evaluateBlindingPolynomial(peerId);
            sendMessage(new DKGShareMsg(caID, s_ij, t_ij), (short) (BASE_PROTOCOL_ID + peerId), entry.getKey());
        }

        checkSharePhaseComplete();
    }

    private void handleShare(DKGShareMsg msg, Host from, short sourceProto, int channel) {
        int sender = msg.getSenderID();
        if (disqualifiedIds.contains(sender)) return;

        List<GroupElement> senderCommitments = receivedCommitments.get(sender);
        if (senderCommitments == null) {
            System.out.println("[CA-" + caID + "] Received a share from CA-" + sender + " before its reveal was accepted. Ignoring...");
            return;
        }

        boolean valid = CA.verifyShare(msg.getSecretShare(), msg.getBlindingShare(), senderCommitments, caID, g1, h1, pairing.getZn());
        if (!valid) {
            System.out.println("[CA-" + caID + "] CA-" + sender + " DISQUALIFIED: share failed verification");
            disqualifiedIds.add(sender);
            broadcastComplaint(sender, "share failed verification");
            checkSharePhaseComplete();
            return;
        }

        receivedSecretShares.put(sender, msg.getSecretShare());

        if (state == DkgState.AWAITING_SHARES)
            checkSharePhaseComplete();
    }

    private void checkSharePhaseComplete() {
        if (state != DkgState.AWAITING_SHARES) return;

        Set<Integer> accounted = new HashSet<>(receivedSecretShares.keySet());
        accounted.addAll(disqualifiedIds);
        if (accounted.size() < n) return;

        Set<Integer> qualifiedIds = new HashSet<>(receivedCommitments.keySet());
        qualifiedIds.removeAll(disqualifiedIds);

        if (qualifiedIds.size() < threshold) {
            System.out.println("[CA-" + caID + "] DKG FAILED: only " + qualifiedIds.size() + " good CAs remain, need at least " + threshold );
            return;
        }

        List<Zn.ZnElement> shares = new ArrayList<>();
        List<GroupElement> pkG1s = new ArrayList<>();
        List<GroupElement> pkG2s = new ArrayList<>();
        for (int qualifiedId : qualifiedIds) {
            shares.add(receivedSecretShares.get(qualifiedId));
            pkG1s.add(receivedPubKeyG1.get(qualifiedId));
            pkG2s.add(receivedPubKeyG2.get(qualifiedId));
        }

        cryptoCA.finalizeDKG(shares, pkG1s, pkG2s);
        state = DkgState.DONE;
        System.out.println("[CA-" + caID + "] DKG COMPLETE. Master keys established with " + qualifiedIds.size() + " good CAs");
    }

    private void handleComplaint(DKGComplaintMsg msg, Host from, short sourceProto, int channel) {
        System.out.println("[CA-" + caID + "] Complaint from CA-" + msg.getSenderID() + " against CA-" + msg.getAccusedId() + ": " + msg.getReason());
        disqualifiedIds.add(msg.getAccusedId());

        if (state == DkgState.AWAITING_REVEALS) checkRevealPhaseComplete();
        else if (state == DkgState.AWAITING_SHARES) checkSharePhaseComplete();
    }

    private void broadcastComplaint(int accusedId, String reason) {
        DKGComplaintMsg complaint = new DKGComplaintMsg(caID, accusedId, reason);
        for (Map.Entry<Host, Integer> entry : hostToPeerId.entrySet()) {
            if (entry.getValue() == accusedId) continue;
            sendMessage(complaint, (short) (BASE_PROTOCOL_ID + entry.getValue()), entry.getKey());
        }
    }

    private void handleMasterPubKeyRequest(MasterPubKeyRequestMsg msg, Host from, short sourceProto, int channel) {
        if (state != DkgState.DONE) {
            System.out.println("[CA-" + caID + "] Master public key requested before DKG finished. Ignoring...");
            return;
        }
        openConnection(from, channelID);
        sendMessage(new MasterPubKeyReplyMsg(cryptoCA.getMasterPubKeyG1(), cryptoCA.getMasterPubKeyG2()), sourceProto, from);
    }

    private void handleCredentialRequest(CredentialRequestMsg msg, Host from, short sourceProto, int channel) {
        if (state != DkgState.DONE) {
            System.out.println("[CA-" + caID + "] Credential requested before DKG finished. Ignoring...");
            return;
        }
        System.out.println("[CA-" + caID + "] Processing Blind Commitment from " + from);

        GroupElement signatureShare = cryptoCA.issueSignatureShare(msg.getBlindedCommitment());

        CredentialReplyMsg reply = new CredentialReplyMsg(this.caID, signatureShare);

        System.out.println("[CA-" + caID + "] Opening outbound reply channel back to: " + from);
        openConnection(from, channelID);

        System.out.println("[CA-" + caID + "] Dispatching partial share back to " + from);
        sendMessage(reply, sourceProto, from);
    }

}
