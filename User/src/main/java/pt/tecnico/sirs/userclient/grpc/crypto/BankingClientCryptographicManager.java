package pt.tecnico.sirs.userclient.grpc.crypto;

import pt.tecnico.sirs.contract.bankserver.BankServer.*;
import pt.tecnico.sirs.cryptology.Base;
import pt.tecnico.sirs.cryptology.Operations;
import pt.tecnico.sirs.utils.Utils;

import java.security.NoSuchAlgorithmException;

public class BankingClientCryptographicManager extends BankingClientCryptographicCore implements Base.KeyManager {
    private final int MOCK_HASH = 0;
    public BankingClientCryptographicManager(
            String ivPath,
            String secretKeyPath,
            String publicKeyPath,
            String privateKeyPath
    ) {
        super();
        this.addIvPath(MOCK_HASH, ivPath);
        this.addSecretKeyPath(MOCK_HASH, secretKeyPath);
        this.addPublicKeyPath(MOCK_HASH, publicKeyPath);
        this.addPrivateKeyPath(MOCK_HASH, privateKeyPath);
    }

    public String encryptPassword(String password) throws NoSuchAlgorithmException {
        return Utils.byteToHex(Operations.hash(password.getBytes()));
    }

    public <P> P encrypt(P object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public <P> boolean check(P object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public <P> P decrypt(P object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public BalanceRequest encrypt(BalanceRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(BalanceResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public BalanceResponse decrypt(BalanceResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public CreateAccountRequest encrypt(CreateAccountRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(CreateAccountResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public CreateAccountResponse decrypt(CreateAccountResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public DeleteAccountRequest encrypt(DeleteAccountRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(DeleteAccountResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public DeleteAccountResponse decrypt(DeleteAccountResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public GetMovementsRequest encrypt(GetMovementsRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(GetMovementsResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public GetMovementsResponse decrypt(GetMovementsResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public AddExpenseRequest encrypt(AddExpenseRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(AddExpenseResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public AddExpenseResponse decrypt(AddExpenseResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public OrderPaymentRequest encrypt(OrderPaymentRequest object) throws Exception {
        return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public boolean check(OrderPaymentResponse object) throws Exception {
        return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }

    public OrderPaymentResponse decrypt(OrderPaymentResponse object) throws Exception {
        return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
    }
}
