package dittor.tor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

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

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("[DA-Server] Listening for Tor connection on port " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        BufferedReader in = new BufferedReader(
                                new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
                        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    String request = in.readLine();
                    if (request != null && request.startsWith("VALIDATE")) {
                        String payload = request.substring(9).trim(); // extract after VALIDATE
                        boolean isValid = false;

                        try {
                            // context|pkStr|nymStr|zkpStr|proofChallengeStr|proofResponseStr
                            String[] parts = payload.split("\\|");

                            if (parts.length == 6) {
                                String context = parts[0];
                                String pkStr = parts[1];
                                String nymStr = parts[2];
                                String zkpStr = parts[3];
                                String proofChallengeStr = parts[4];
                                String proofResponseStr = parts[5];

                                JSONConverter jsonConverter = new JSONConverter();

                                GroupElement pk = pairing.getG2().restoreElement(jsonConverter.deserialize(pkStr));
                                GroupElement nym = pairing.getGT().restoreElement(jsonConverter.deserialize(nymStr));
                                GroupElement zkp = pairing.getG1().restoreElement(jsonConverter.deserialize(zkpStr));

                                Zn zn = pairing.getZn();
                                ZnElement challenge = zn.restoreElement(jsonConverter.deserialize(proofChallengeStr));
                                ZnElement response = zn.restoreElement(jsonConverter.deserialize(proofResponseStr));

                                VRFResult vrfData = new VRFResult(nym, zkp);
                                Proof identityProof = new Proof(challenge, response);

                                System.out.println("[DA-Server] Processing Tor descriptor tokens...");
                                boolean isVrfValid = cryptoDA.verifyVrf(pk, vrfData, context);
                                boolean isZkpValid = cryptoDA.verifyIdentityProof(pk, identityProof, context);

                                isValid = isVrfValid && isZkpValid;
                            } else {
                                System.err.println(
                                        "[DA-Server] Malformed payload! Expected 6 components, got: " + parts.length);
                            }
                        } catch (Exception cryptoEx) {
                            System.err.println("[DA-Server] Crypto reconstruction failed: " + cryptoEx.getMessage());
                            cryptoEx.printStackTrace();
                        }

                        if (isValid) {
                            out.println("VALID");
                            System.out.println("[DA-Server] Pseudonym verified successfully");
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
