package pt.tecnico.sirs.databaseserver.domain;

import pt.tecnico.sirs.databaseserver.dto.OrderPaymentDto;
import pt.tecnico.sirs.databaseserver.dto.MovementDto;

import javax.persistence.*;

import org.hibernate.annotations.ColumnTransformer;

import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Entity
public class Movement implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          id,
          'movement'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private long id;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          movementNumber,
          'movement'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private final UUID movementNumber;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          movementDate,
          'movement'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private LocalDateTime movementDate;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          amount,
          'movement'
      )::numeric
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private BigDecimal amount;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          description,
          'movement'
      )
      """, write = """
      pgp_sym_encrypt(
          ?,
          'movement'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private String description;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          accountFrom,
          'movement'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private UUID accountFrom;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          accountTo,
          'movement'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'movement'
      )
      """)
  @Column(columnDefinition = "bytea")
  private UUID accountTo;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          currency,
          'account'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'account'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private String currency;

  public Movement(MovementDto movement) {
    this();
    this.accountFrom = movement.accountFrom();
    this.movementDate = movement.date();
    this.amount = movement.amount();
    this.description = movement.description();
    this.currency = movement.currency();
  }

  public Movement(OrderPaymentDto order) {
    this();
    this.accountFrom = order.accountFrom();
    this.accountTo = order.accountTo();
    this.movementDate = order.date();
    this.amount = order.amount();
    this.description = order.description();
    this.currency = order.currency();
  }

  public Movement() {
    this.movementNumber = UUID.randomUUID();
  }

  public void setId(Long id) {
    this.id = id;
  }

  public Long getId() {
    return id;
  }

  public UUID getMovementNumber() {
    return movementNumber;
  }

  public LocalDateTime getMovementDate() {
    return movementDate;
  }

  public BigDecimal getAmount() {
    return amount;
  }

  public String getDescription() {
    return description;
  }

  public String getCurrency() {
    return currency;
  }

  public Optional<UUID> getFromAccountNumber() {
    return accountFrom == null ? Optional.empty() : Optional.of(accountFrom);
  }

  public Optional<UUID> getDestinationAccountNumber() {
    return accountTo == null ? Optional.empty() : Optional.of(accountTo);
  }
}
