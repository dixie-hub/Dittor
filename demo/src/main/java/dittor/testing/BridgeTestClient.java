package dittor.testing;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

// Cliente do socket para testar o DAServer diretamente, sem Tor nem Chutney, usado nos testes "Bridge"
public class BridgeTestClient {
    
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usar BridgeTestClient <ficheiro-payload> [host] [porta] [repeticoes] [ficheiro-csv]");
            System.exit(1);
        }

        String payloadFile = args[0];
        String host = args.length > 1 ? args[1] : "127.0.0.1";
        int port = args.length > 2 ? Integer.parseInt(args[2]) : 8081;
        int repeat = args.length > 3 ? Integer.parseInt(args[3]) : 1;
        String csvFile = args.length > 4 ? args[4] : null;

        String payload = new String(Files.readAllBytes(Paths.get(payloadFile)), StandardCharsets.UTF_8).trim();

        FileWriter csv = csvFile != null ? new FileWriter(csvFile, true) : null;

        for (int i = 1; i <= repeat; i++) {
            long start = System.nanoTime();
            String response;
            try {
                response = sendValidate(host, port, payload);
            } catch (IOException e) {
                response = "CONNECTION_ERROR: " + e.getMessage();
            }
            double elapsedMs = (System.nanoTime() - start) / 1_000_000.0;

            System.out.printf("[%d/%d] %.2fms -> %s%n", i, repeat, elapsedMs, response);

            if (csv != null) {
                csv.write(System.currentTimeMillis() + "," + payloadFile + "," + i + "," + elapsedMs + "," + response + "\n");
            }
        }

        if (csv != null) {
            csv.close();
        }
    }

    private static String sendValidate(String host, int port, String payload) throws IOException {
        try (Socket socket = new Socket(host, port);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
            out.println("VALIDATE " + payload);
            String response = in.readLine();
            return response != null ? response : "NO_RESPONSE";
        }
    }
}
