package dittor.tor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zn.ZnElement;

import dittor.crypto.DA;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.VRFResult;

public class DAServer implements Runnable {

    private final int port;
    private final BilinearGroup pairing;
    private final DA cryptoDA;

    public DAServer(int port, BilinearGroup pairing, DA cryptoDA) {
        this.port = port;
        this.pairing = pairing;
        this.cryptoDA = cryptoDA;
    }

    private String sanitizeJsonString(String str) {
        if (str == null) return null;
        str = str.trim();
        if (!str.startsWith("{") && !str.startsWith("[") && !str.startsWith("\"")) {
            return "\"" + str + "\"";
        }
        return str;
    }

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port, 0, java.net.InetAddress.getByName("0.0.0.0"))) {
            System.out.println("[DA-Server] Listening for Tor connection on port " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        BufferedReader in = new BufferedReader(
                                new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
                        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    String request = in.readLine();
                    if (request != null && request.startsWith("VALIDATE")) {
                        String payload = request.substring(9).trim();
                        boolean isValid = false;

                        try {
                            String[] parts = payload.split("\\|");

                            if (parts.length == 10) {
                                JSONConverter jsonConverter = new JSONConverter();
                                String context = parts[0].trim();
                                String pkStr = sanitizeJsonString(parts[1]);
                                String nymStr = sanitizeJsonString(parts[2]);
                                String zkpStr = sanitizeJsonString(parts[3]);
                                String g1xStr = sanitizeJsonString(parts[4]);
                                String credentialStr = sanitizeJsonString(parts[5]);
                                String dleqChallengeStr = sanitizeJsonString(parts[6]);
                                String dleqResponseStr = sanitizeJsonString(parts[7]);
                                String nodeId = parts[8].trim();
                                //String familyIdsRaw = parts[9].trim();
                                                                String familyIdsRaw = parts[9].trim();
                                System.out.println("[DEBUG] familyIdsRaw recebido = '" + familyIdsRaw + "'");

                                if (!pkStr.contains("mock_pk")) {
                                    GroupElement pk = pairing.getG2().restoreElement(jsonConverter.deserialize(pkStr));
                                    GroupElement nym = pairing.getGT().restoreElement(jsonConverter.deserialize(nymStr));
                                    GroupElement zkp = pairing.getG1().restoreElement(jsonConverter.deserialize(zkpStr));
                                    GroupElement g1x = pairing.getG1().restoreElement(jsonConverter.deserialize(g1xStr));
                                    GroupElement credential = pairing.getG1().restoreElement(jsonConverter.deserialize(credentialStr));

                                    Zn zn = pairing.getZn();
                                    ZnElement dleqChallenge = zn.restoreElement(jsonConverter.deserialize(dleqChallengeStr));
                                    ZnElement dleqResponse = zn.restoreElement(jsonConverter.deserialize(dleqResponseStr));

                                    VRFResult vrfData = new VRFResult(nym, zkp);
                                    Proof dleqProof = new Proof(dleqChallenge, dleqResponse);

                                    System.out.println("[DA-Server] Processing Tor descriptor tokens...");
                                    boolean isVrfValid = cryptoDA.verifyVrf(pk, vrfData, context);
                                    boolean isCredentialValid = cryptoDA.verifyCredentialLinkage(pk, g1x, credential, dleqProof, context);
                                    System.out.println("[DA-Server] VRF Evaluation Outcome: " + (isVrfValid ? "PASS" : "FAIL"));
                                    System.out.println("[DA-Server] Credential Linkage Outcome: " + (isCredentialValid ? "PASS" : "FAIL"));

                                    if (isVrfValid && isCredentialValid) {
                                        Set<String> familyIds = familyIdsRaw.equals("-") ? new HashSet<>() : new HashSet<>(Arrays.asList(familyIdsRaw.split(",")));
                                        isValid = cryptoDA.registerNode(context, nym, nodeId, familyIds);
                                    } else
                                        isValid = false;
                                }
                            } else {
                                System.err.println("[DA-Server] Malformed payload! Expected 10 components, got: " + parts.length);
                            }
                        } catch (Exception cryptoEx) {
                            System.err.println("[DA-Server] Crypto reconstruction failed: " + cryptoEx.getMessage());
                            cryptoEx.printStackTrace();
                        }

                        if (isValid) {
                            out.println("VALID");
                            System.out.println("[DA-Server] Pseudonym verified successfully!");
                        } else {
                            out.println("INVALID");
                            System.err.println("[DA-Server] Pseudonym rejected");
                        }
                    }
                    clientSocket.close();
                } catch (Exception clientEx) {
                    System.err.println("[DA-Server] Connection error: " + clientEx.getMessage());
                    clientEx.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.err.println("[DA-Server] Server exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}