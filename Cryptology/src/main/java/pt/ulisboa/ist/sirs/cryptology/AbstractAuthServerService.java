package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.dto.DiffieHellmanParams;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class AbstractAuthServerService {
  public static synchronized DiffieHellmanParams diffieHellmanExchange(
    String symmetricKeyPath, String IVPath, byte[] clientPubEnc
  ) throws Exception {
    KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubEnc);
    PublicKey clientPublic = serverKeyFac.generatePublic(x509KeySpec);

    // Server gets DH parameters from client's public Key
    DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey) clientPublic).getParams();

    // Server creates his own DH key pair
    KeyPairGenerator serverKeypairGen = KeyPairGenerator.getInstance("DH");
    serverKeypairGen.initialize(dhParamFromClientPubKey);
    KeyPair serverKeypair = serverKeypairGen.generateKeyPair();

    // Server creates and initializes his DH KeyAgreement object
    KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
    serverKeyAgree.init(serverKeypair.getPrivate());

    // Server encodes his public key, and sends it to client.
    byte[] serverPubKeyEnc = serverKeypair.getPublic().getEncoded();

    /*
     * Server uses client's public key for the first (and only) phase
     * of his part of the DH protocol.
     */
    serverKeyAgree.doPhase(clientPublic, true);
    byte[] sharedSecret = serverKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

    // Server encrypts, using AES in CBC mode
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    cipher.doFinal(Base.generateRandom(Long.MAX_VALUE).toString().getBytes());

    // Retrieve the parameter that was used, and transfer it to Alice in encoded
    // format
    byte[] encodedParams = cipher.getParameters().getEncoded();
    byte[] temp = Arrays.copyOfRange(encodedParams, 10, 14);
    byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

    // Cache client crypto data
    Utils.writeBytesToFile(aesKey.getEncoded(), symmetricKeyPath);
    Utils.writeBytesToFile(iv, IVPath);

    return new DiffieHellmanParams(serverPubKeyEnc, encodedParams);
  }
}
