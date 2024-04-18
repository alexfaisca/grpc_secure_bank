package pt.tecnico.sirs.databaseserver.repository.service.engine;

import pt.tecnico.sirs.databaseserver.domain.Payment;
import pt.tecnico.sirs.databaseserver.dto.*;
import pt.tecnico.sirs.databaseserver.repository.exceptions.IllegalPaymentOrderBalance;
import pt.tecnico.sirs.databaseserver.repository.exceptions.NoSuchAccountException;
import pt.tecnico.sirs.databaseserver.repository.exceptions.NoSuchAccountHolderException;
import pt.tecnico.sirs.databaseserver.repository.exceptions.NotEnoughBalanceException;
import pt.tecnico.sirs.databaseserver.repository.service.engine.impl.PaymentDAO;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.UUID;

public class PaymentService {
  private final PaymentDAO paymentDAO;
  private final ApprovalService approvalService;
  private final MovementService movementService;
  private final BankAccountHolderService holderService;
  private final BankAccountService bankAccountService;

  public PaymentService(PaymentDAO paymentDAO, ApprovalService approvalService, MovementService movementService,
      BankAccountHolderService holderService, BankAccountService bankAccountService) {
    this.paymentDAO = paymentDAO;
    this.approvalService = approvalService;
    this.movementService = movementService;
    this.holderService = holderService;
    this.bankAccountService = bankAccountService;
  }

  private static PaymentDto toDto(Payment payment) {
    return new PaymentDto(
        payment.getAccountFrom(),
        payment.getAccountTo(),
        payment.getPaymentRef(),
        payment.getAmount(),
        payment.getRequestDate(),
        payment.getDescription(),
        payment.getAuthorized(),
        payment.getMovementRef());
  }

  private void addPaymentApproval(Payment payment, HolderDto holderDto, LocalDateTime date) {
    ApprovalDto ignored = approvalService.addPaymentApproval(payment.getPaymentRef(), holderDto.number(), date);
  }

  private boolean checkPaymentApproval(Payment payment) {
    HashSet<UUID> approvals = new HashSet<>(
        approvalService.getPaymentApprovals(payment.getPaymentRef())
            .stream().map(ApprovalDto::holder).toList());
    return approvals.containsAll(
        holderService.getHolderByAccountNumber(payment.getAccountFrom())
            .stream().map(HolderDto::number).toList());
  }

  private void approvePayment(Payment payment, LocalDateTime date) {
    MovementDto movementDto = movementService.addPayment(
        new OrderPaymentDto(
            payment.getAccountFrom(),
            payment.getAccountTo(),
            date,
            payment.getAmount(),
            payment.getDescription(),
            payment.getCurrency()));
    payment.setMovementRef(movementDto.movementRef());
    payment.setAuthorized(true);
  }

  public PaymentDto orderPayment(String username, LocalDateTime date, BigDecimal amount, String description,
      String recipient) {
    if (amount.compareTo(BigDecimal.ZERO) < 0)
      throw new IllegalPaymentOrderBalance();
    HolderDto holderDto = holderService.getHolderByName(username).orElseThrow(NoSuchAccountHolderException::new);
    BankAccountDto bankAccount = bankAccountService.getByHolder(holderDto.name())
        .orElseThrow(NoSuchAccountException::new);
    if (amount.compareTo(bankAccount.balance()) > 0)
      throw new NotEnoughBalanceException();

    Payment payment = paymentDAO.getPaymentByAccountFromAndAccountToAndAmountAndDescription(
        holderDto.accountNumber(),
        holderService.getHolderByName(recipient).orElseThrow(NoSuchAccountHolderException::new).accountNumber(),
        amount,
        description).orElseGet(() -> {
          Payment p = new Payment(
              holderDto.accountNumber(),
              holderService.getHolderByName(recipient).orElseThrow(NoSuchAccountHolderException::new).accountNumber(),
              amount,
              date,
              description,
              bankAccount.currency());
          p.setId(paymentDAO.save(p));
          return p;
        });

    addPaymentApproval(payment, holderDto, date);
    if (checkPaymentApproval(payment))
      approvePayment(payment, date);

    return toDto(payment);
  }
}
