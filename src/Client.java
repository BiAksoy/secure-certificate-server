// Bilal Aksoy - 20200601004
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 1907;
    private static final String PUBLIC_KEY_FILE = "publicKey.pem";

    private final PublicKey publicKey;

    public Client() {
        publicKey = readCAPublicKey();
    }

    private PublicKey readCAPublicKey() {
        try {
            FileInputStream fis = new FileInputStream(PUBLIC_KEY_FILE);
            byte[] publicKeyBytes = new byte[fis.available()];
            fis.read(publicKeyBytes);
            fis.close();

            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void sendGetCommand(String alias) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT)) {
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            out.println("GET " + alias);

            String statusCodeStr = in.readLine();
            int statusCode = Integer.parseInt(statusCodeStr);

            if (statusCode == 200) {
                String fullName = in.readLine();
                String receivedAlias = in.readLine();
                String publicKeyStr = in.readLine();
                long expirationDateMillis = Long.parseLong(in.readLine());
                String signature = in.readLine();

                PublicKey publicKey = decodePublicKey(publicKeyStr);
                Date expirationDate = new Date(expirationDateMillis);

                String data = fullName + receivedAlias + publicKey + expirationDate;

                if (verifySignature(signature, data)) {
                    if (expirationDate.after(new Date())) {
                        System.out.println("Certificate of user " + fullName + " is verified.");
                    } else {
                        System.out.println("Error: Certificate of user " + fullName + " has expired.");
                    }
                } else {
                    System.out.println("Error: Signature verification failed for user " + fullName);
                }
            } else if (statusCode == 400) {
                System.out.println("Error: Bad Request");
            } else if (statusCode == 401) {
                System.out.println("Error: User not found");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private PublicKey decodePublicKey(String publicKeyStr) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean verifySignature(String signature, String data) {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(data.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sign.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.sendGetCommand("c1");
    }
}
