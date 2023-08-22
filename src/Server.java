// Bilal Aksoy - 20200601004

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Server {
    private static final int PORT = 1907;
    private static final String PUBLIC_KEY_FILE = "publicKey.pem";

    private PrivateKey privateKey;
    private final Map<String, Certificate> certificateMap;

    public Server() {
        generateKeyPair();
        certificateMap = new HashMap<>();
        createCertificates();
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();

            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE);
            fos.write(spec.getEncoded());
            fos.close();

            System.out.println("Server: Public key generated and saved to " + PUBLIC_KEY_FILE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createCertificates() {
        for (int i = 1; i <= 5; i++) {
            String fullName = "Client " + i;
            String alias = "c" + i;
            PublicKey publicKey = generateRandomPublicKey();
            Date expirationDate = new Date(System.currentTimeMillis() + 15000);

            Certificate certificate = new Certificate(fullName, alias, publicKey, expirationDate, privateKey);
            certificateMap.put(alias, certificate);
        }
    }

    private PublicKey generateRandomPublicKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server: Listening on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                Thread thread = new ClientHandler(clientSocket);
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private class ClientHandler extends Thread {
        private final Socket clientSocket;
        private PrintWriter out;

        public ClientHandler(Socket socket) {
            clientSocket = socket;
        }

        public void run() {
            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                String request = in.readLine();
                if (request != null) {
                    String[] commandParts = request.split(" ");
                    if (commandParts.length == 2 && commandParts[0].equals("GET")) {
                        String alias = commandParts[1];
                        handleGetCommand(alias);
                    } else {
                        sendStatusCode(400);
                    }
                }

                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private void handleGetCommand(String alias) {
            Certificate certificate = certificateMap.get(alias);
            if (certificate != null) {
                sendStatusCode(200);
                sendCertificateComponents(certificate);
            } else {
                sendStatusCode(401);
            }
        }

        private void sendStatusCode(int statusCode) {
            out.println(statusCode);
        }

        private void sendCertificateComponents(Certificate certificate) {
            out.println(certificate.getFullName());
            out.println(certificate.getAlias());
            out.println(encodePublicKey(certificate.getPublicKey()));
            out.println(certificate.getExpirationDate().getTime());
            out.println(certificate.getSignature());
        }

        private String encodePublicKey(PublicKey publicKey) {
            byte[] publicKeyBytes = publicKey.getEncoded();
            return Base64.getEncoder().encodeToString(publicKeyBytes);
        }
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.start();
    }
}
