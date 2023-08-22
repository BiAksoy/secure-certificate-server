// Bilal Aksoy - 20200601004
import java.security.*;
import java.util.Base64;
import java.util.Date;

public class Certificate {
    private final String fullName;
    private final String alias;
    private final PublicKey publicKey;
    private final Date expirationDate;
    private final String signature;

    public Certificate(String fullName, String alias, PublicKey publicKey, Date expirationDate, PrivateKey privateKey) {
        this.fullName = fullName;
        this.alias = alias;
        this.publicKey = publicKey;
        this.expirationDate = expirationDate;
        this.signature = generateSignature(privateKey);
    }

    private String generateSignature(PrivateKey privateKey) {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privateKey);
            sign.update(getCertificateData());
            byte[] signatureBytes = sign.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] getCertificateData() {
        return (fullName + alias + publicKey + expirationDate).getBytes();
    }

    public String getFullName() {
        return fullName;
    }

    public String getAlias() {
        return alias;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public String getSignature() {
        return signature;
    }
}
