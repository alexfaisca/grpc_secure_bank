package pt.ulisboa.ist.sirs.bankserver.domain;

import pt.ulisboa.ist.sirs.bankserver.grpc.BankService;
import pt.ulisboa.ist.sirs.bankserver.grpc.crypto.AuthenticationClientCryptographicManager;

import java.io.IOException;

public class BankState {
  public static class BankStateBuilder {
    private final boolean debug;
    private final BankService service;
    public BankStateBuilder(
      String serverService,
      String serverName,
      String host,
      Integer port,
      String authenticationServerAddress,
      Integer authenticationServerPort,
      String trustChainPath,
      String certChainPath,
      String connectionKeyPath,
      AuthenticationClientCryptographicManager crypto,
      boolean debug
    ) throws Exception {
      this.debug = debug;
      this.service = new BankService.BankServiceBuilder(
        serverService,
        serverName,
        host,
        port,
        authenticationServerAddress,
        authenticationServerPort,
        certChainPath,
        connectionKeyPath,
        trustChainPath,
        crypto,
        debug
      ).build();
    }
    public BankState build() {
      return new BankState(this);
    }

  }

  private final boolean debug;
  private final BankService service;

  private BankState(BankStateBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
  }

  public String getBankingService() {
    return service.getServerServiceName();
  }

  public Integer getServerPort() {
    return service.getServerPort();
  }

  public String getServerAddress() {
    return service.getServerAddress();
  }

  public String getServerName() {
    return service.getServerName();
  }

  public boolean isDebug() {
    return debug;
  }

  public synchronized byte[] authenticate(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      byte[] response = service.authenticate(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
      return response;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized byte[] stillAlive(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      byte[] response = service.stillAlive(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
      return response;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void createAccount(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.createAccount(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void deleteAccount(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.deleteAccount(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized byte[] balance(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      byte[] response = service.balance(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
      return response;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void addExpense(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.addExpense(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized byte[] getMovements(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      byte[] response = service.getMovements(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
      return response;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void orderPayment(byte[] request) {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.orderPayment(request);
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void register() {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.register();
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized void delete() {
    try {
      if (isDebug())
        System.out.println("\t\tBankState: delegate request");
      service.delete();
      if (isDebug())
        System.out.println("\t\tBankState: return");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
