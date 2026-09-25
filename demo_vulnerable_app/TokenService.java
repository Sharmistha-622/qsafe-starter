// DEMO ONLY - intentionally quantum-vulnerable code
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import javax.crypto.KeyAgreement;

public class TokenService {
    public KeyPair rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }
    public KeyAgreement dh() throws Exception {
        return KeyAgreement.getInstance("DH");
    }
}
