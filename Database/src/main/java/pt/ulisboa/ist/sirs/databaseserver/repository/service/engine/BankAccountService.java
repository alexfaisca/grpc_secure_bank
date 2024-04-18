package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine;

import pt.ulisboa.ist.sirs.databaseserver.domain.BankAccount;
import pt.ulisboa.ist.sirs.databaseserver.dto.BankAccountDto;
import pt.ulisboa.ist.sirs.databaseserver.dto.HolderDto;
import pt.ulisboa.ist.sirs.databaseserver.repository.exceptions.BadHolderException;
import pt.ulisboa.ist.sirs.databaseserver.repository.exceptions.NoSuchAccountException;
import pt.ulisboa.ist.sirs.databaseserver.repository.exceptions.NoSuchAccountHolderException;
import pt.ulisboa.ist.sirs.databaseserver.repository.exceptions.NotEnoughBalanceException;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl.BankAccountDAO;

import java.math.BigDecimal;
import java.util.*;

public class BankAccountService {
  private final BankAccountDAO bankAccountDAO;
  private final BankAccountHolderService bankAccountHolderService;

  public BankAccountService(BankAccountDAO bankAccountDAO, BankAccountHolderService bankAccountHolderService) {
    this.bankAccountDAO = bankAccountDAO;
    this.bankAccountHolderService = bankAccountHolderService;
  }

  private static BankAccountDto toDto(BankAccount a) {
    return new BankAccountDto(
        a.getNumber(),
        a.getPassword(),
        a.getBalance(),
        a.getCurrency());
  }

  public Optional<BankAccountDto> getByHolder(String username) {
    return bankAccountDAO.findByNumber(bankAccountHolderService.getHolderByName(username)
        .orElseThrow(NoSuchAccountHolderException::new).accountNumber()).map(BankAccountService::toDto);
  }

  public BankAccountDto createAccount(List<String> holders, byte[] passwords, BigDecimal initialDeposit) {

    if (holders.stream().map(bankAccountHolderService::checkExists).anyMatch(t -> t == Boolean.TRUE))
      throw new BadHolderException();
    BankAccount account = new BankAccount(passwords, initialDeposit);
    account.setId(bankAccountDAO.save(account));
    holders.forEach(h -> {
      HolderDto ignored = bankAccountHolderService.addHolder(h, account.getNumber());
    });
    return toDto(account);
  }

  public void deleteAccount(String username) {
    UUID accountNumber = bankAccountHolderService.getHolderByName(username)
        .orElseThrow(NoSuchAccountHolderException::new).accountNumber();
    bankAccountHolderService.deleteHolderByAccountNumber(accountNumber);
    bankAccountDAO.delete(bankAccountDAO.findByNumber(accountNumber).orElseThrow(NoSuchAccountException::new));
  }

  public boolean passwordCheck(String username, byte[] password) {
    return !Arrays.equals(
        bankAccountDAO.findByNumber(
            bankAccountHolderService.getHolderByName(username).orElseThrow(NoSuchAccountHolderException::new)
                .accountNumber())
            .orElseThrow(NoSuchAccountException::new).getPassword(),
        password);
  }

  public BigDecimal getBalance(String username) {
    return bankAccountDAO.findByNumber(
        bankAccountHolderService.getHolderByName(username).orElseThrow(NoSuchAccountHolderException::new)
            .accountNumber())
        .orElseThrow(NoSuchAccountException::new).getBalance();
  }

  public void move(UUID accountFrom, UUID accountTo, BigDecimal amount) {
    BankAccount bankAccountFrom = bankAccountDAO.findByNumber(accountFrom).orElseThrow(NoSuchAccountException::new);
    if (bankAccountFrom.getBalance().compareTo(amount) < 0)
      throw new NotEnoughBalanceException();
    BankAccount bankAccountTo = bankAccountDAO.findByNumber(accountTo).orElseThrow(NoSuchAccountException::new);
    bankAccountTo.moveBalance(amount);
    bankAccountFrom.moveBalance(amount.negate());
    bankAccountDAO.save(bankAccountFrom);
    bankAccountDAO.save(bankAccountTo);
  }
}
