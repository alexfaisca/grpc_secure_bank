package pt.ulisboa.ist.sirs.bankserver.grpc;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc.DatabaseServiceBlockingStub;

import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.TlsChannelCredentials;
import java.io.File;
import java.io.IOException;

public class BankService {

  public static class BankServiceBuilder {

    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;
    private final DatabaseServiceBlockingStub stub;

    public BankServiceBuilder(
        String service,
        String qualifier,
        String address,
        Integer port,
        String databaseHost,
        Integer databasePort,
        String trustChainPath,
        String certPath,
        String connectionKeyPath,
        boolean debug) throws IOException {
      this.debug = debug;
      this.address = address;
      this.port = port;
      this.service = service;
      this.name = qualifier;
      final ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
          .trustManager(new File(trustChainPath))
          .keyManager(new File(certPath), new File(connectionKeyPath))
          .build();
      final Channel channel = Grpc.newChannelBuilderForAddress(
          databaseHost,
          databasePort,
          credentials).build();
      this.stub = DatabaseServiceGrpc.newBlockingStub(channel);
    }

    public BankService build() {
      return new BankService(this);
    }
  }

  private final boolean debug;
  private final String address;
  private final Integer port;
  private final String service;
  private final String name;
  private final DatabaseServiceBlockingStub stub;

  public BankService(BankServiceBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
    this.name = builder.name;
    this.address = builder.address;
    this.port = builder.port;
    this.stub = builder.stub;
  }

  public String getServerName() {
    return this.name;
  }

  public String getService() {
    return this.service;
  }

  public String getServerAddress() {
    return this.address;
  }

  public Integer getServerPort() {
    return this.port;
  }

  public boolean isDebug() {
    return this.debug;
  }

  public synchronized byte[] authenticate(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: call authentication stub");
    AuthenticateResponse authenticateResponse = stub.authenticate(AuthenticateRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
    if (isDebug())
      System.out.println("\t\t\tBankService: return response");
    return authenticateResponse.getResponse().toByteArray();
  }

  public synchronized byte[] stillAlive(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: call authentication stub");
    StillAliveResponse stillAliveResponse = stub.stillAlive(StillAliveRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
    if (isDebug())
      System.out.println("\t\t\tBankService: return response");
    return stillAliveResponse.getResponse().toByteArray();
  }

  public synchronized void createAccount(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");

    CreateAccountResponse ignored = stub.createAccount(CreateAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
  }

  public synchronized void deleteAccount(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");
    DeleteAccountResponse ignored = stub.deleteAccount(DeleteAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
  }

  public synchronized byte[] balance(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");
    BalanceResponse balanceResponse = stub.balance(BalanceRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());

    if (isDebug())
      System.out.println("\t\t\tBankService: decrypt deserialize response");
    return balanceResponse.getResponse().toByteArray();
  }

  public synchronized void addExpense(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");
    AddExpenseResponse ignored = stub.addExpense(AddExpenseRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
  }

  public synchronized byte[] getMovements(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");
    GetMovementsResponse getMovementsResponse = stub.getMovements(GetMovementsRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());

    if (isDebug())
      System.out.println("\t\t\tBankService: decrypt deserialize response");
    return getMovementsResponse.getResponse().toByteArray();
  }

  public synchronized void orderPayment(byte[] request) {
    if (isDebug())
      System.out.println("\t\t\tBankService: parse serialize and encrypt request");
    OrderPaymentResponse ignored = stub.orderPayment(OrderPaymentRequest.newBuilder().setRequest(
        ByteString.copyFrom(request)).build());
  }

  public void register() {
  }

  public void delete() {
  }
}
