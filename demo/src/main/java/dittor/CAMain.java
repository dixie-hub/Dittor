package dittor;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup.GroupChoice;

import dittor.crypto.CA;
import dittor.protocols.CAProtocol;
import pt.unl.fct.di.novasys.babel.core.Babel;
import pt.unl.fct.di.novasys.network.data.Host;

public class CAMain {
    
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: CAMain <caconfig.properties path>");
            System.exit(1);
        }

        Properties config = new Properties();
        try (InputStream in = new FileInputStream(args[0])) {
            config.load(in);
        }

        int caID = Integer.parseInt(config.getProperty("caId"));
        String address = config.getProperty("address", "127.0.0.1");
        int port = Integer.parseInt(config.getProperty("port"));
        int theshold = Integer.parseInt(config.getProperty("threshold"));
        int n = Integer.parseInt(config.getProperty("n"));
        String peersConfig = config.getProperty("peers", "");

        System.out.println("Initializing Bilinear Group...");
        BilinearGroup pairing = new MclBilinearGroup(GroupChoice.BLS12_381);

        GroupElement g1 = pairing.getG1().getGenerator();
        GroupElement h1 = pairing.getHashIntoG1().hash("Dittor-Pedersen-h1-2026");
        GroupElement g2 = pairing.getG2().getGenerator();

        Map<Host, Integer> peerHosts = new HashMap<>();
        if (!peersConfig.trim().isEmpty()) {
            for (String entry : peersConfig.split(",")) {
                String[] parts = entry.trim().split(":"); 
                Host peerHost = new Host(InetAddress.getByName(parts[0]), Integer.parseInt(parts[1]));
                peerHosts.put(peerHost, Integer.parseInt(parts[2]));
            }
        }

        System.out.println("Starting CA-" + caID + " on " + address + ":" + port + "...");
        CA cryptoCA = new CA(caID, pairing);
        CAProtocol caProtocol = new CAProtocol(pairing, cryptoCA, caID, g1, h1, g2);

        Properties caProperties = new Properties();
        caProperties.setProperty("address", address);
        caProperties.setProperty("port", String.valueOf(port));

        Babel babel = Babel.getInstance();
        babel.registerProtocol(caProtocol);
        caProtocol.init(caProperties);
        caProtocol.start();

        Thread.sleep(1000); // tempo para o socket do servidor dar bind

        caProtocol.startDKG(peerHosts, theshold, n);

        System.out.println("[CA-" + caID + "] Running. Waiting for DKG to complete and credential requests...");
    }
}
