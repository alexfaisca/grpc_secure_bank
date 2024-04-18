package pt.tecnico.sirs.databaseserver.repository.service.engine;

import pt.tecnico.sirs.databaseserver.domain.Movement;
import pt.tecnico.sirs.databaseserver.dto.*;
import pt.tecnico.sirs.databaseserver.repository.exceptions.MovementWithNoDestinationAccountException;
import pt.tecnico.sirs.databaseserver.repository.exceptions.MovementWithNoFromAccountException;
import pt.tecnico.sirs.databaseserver.repository.exceptions.NoSuchAccountException;
import pt.tecnico.sirs.databaseserver.repository.exceptions.NoSuchAccountHolderException;
import pt.tecnico.sirs.databaseserver.repository.service.engine.impl.MovementDAO;

import javax.transaction.Transactional;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

public class MovementService {
  private final MovementDAO movementDAO;
  private final BankAccountService bankAccountService;

  public MovementService(MovementDAO movementDAO, BankAccountService bankAccountService) {
    this.movementDAO = movementDAO;
    this.bankAccountService = bankAccountService;
  }

  private static MovementDto toDto(Movement m) {
    return new MovementDto(
        m.getMovementNumber(),
        m.getFromAccountNumber().orElseThrow(MovementWithNoFromAccountException::new),
        m.getMovementDate(),
        m.getAmount(),
        m.getDescription(),
        m.getCurrency());
  }

  @Transactional
  public MovementDto addMovement(String username, LocalDateTime date, BigDecimal amount, String description) {
    BankAccountDto accountDto = bankAccountService.getByHolder(username).orElseThrow(NoSuchAccountException::new);
    Movement movement = new Movement(new MovementDto(
        UUID.randomUUID(),
        accountDto.number(),
        date,
        amount,
        description,
        accountDto.currency()));
    movement.setId(movementDAO.save(movement));
    return toDto(movement);
  }

  public List<MovementDto> getAccountMovements(String username) {
    UUID number = bankAccountService.getByHolder(username).orElseThrow(NoSuchAccountHolderException::new).number();
    List<MovementDto> movements = new ArrayList<>();
    movements.addAll(movementDAO.findByAccountFrom(number).stream()
        .map(m -> new MovementDto(m.getMovementNumber(),
            m.getFromAccountNumber().orElseThrow(MovementWithNoFromAccountException::new), m.getMovementDate(),
            m.getAmount().negate(), m.getDescription(), m.getCurrency()))
        .toList());
    movements.addAll(movementDAO.findByAccountTo(number).stream()
        .map(m -> new MovementDto(m.getMovementNumber(),
            m.getDestinationAccountNumber().orElseThrow(MovementWithNoDestinationAccountException::new),
            m.getMovementDate(), m.getAmount(), m.getDescription(), m.getCurrency()))
        .toList());
    movements.sort(Comparator.comparing(MovementDto::date));
    return movements;
  }

  public MovementDto addPayment(OrderPaymentDto paymentOrder) {
    bankAccountService.move(paymentOrder.accountFrom(), paymentOrder.accountTo(), paymentOrder.amount());
    Movement newMovement = new Movement(paymentOrder);
    newMovement.setId(movementDAO.save(newMovement));
    return toDto(newMovement);
  }
}
