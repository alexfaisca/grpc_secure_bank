package pt.ulisboa.ist.sirs.databaseserver.domain;

import org.hibernate.annotations.ColumnTransformer;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Entity
public class Payment implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          id,
          'payment'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  private Long id;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          accountFrom,
          'payment'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private UUID accountFrom;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          accountTo,
          'payment'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private UUID accountTo;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          paymentRef,
          'payment'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private final UUID paymentRef = UUID.randomUUID();

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          amount,
          'payment'
      )::numeric
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private BigDecimal amount;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          requestDate,
          'payment'
      )::timestamp
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private LocalDateTime requestDate;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          description,
          'payment'
      )
      """, write = """
      pgp_sym_encrypt(
          ?,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private String description;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          authorized,
          'payment'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private boolean authorized;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          movementRef,
          'payment'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'payment'
      )
      """)
  @Column(columnDefinition = "bytea")
  private UUID movementRef;

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

  public Payment() {
  }

  public Payment(UUID accountFrom, UUID accountTo, BigDecimal amount, LocalDateTime date, String description,
      String currency) {
    this.accountFrom = accountFrom;
    this.accountTo = accountTo;
    this.amount = amount;
    this.requestDate = date;
    this.description = description;
    this.authorized = false;
    this.currency = currency;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public UUID getAccountFrom() {
    return accountFrom;
  }

  public UUID getAccountTo() {
    return accountTo;
  }

  public BigDecimal getAmount() {
    return amount;
  }

  public LocalDateTime getRequestDate() {
    return requestDate;
  }

  public String getDescription() {
    return description;
  }

  public UUID getPaymentRef() {
    return paymentRef;
  }

  public void setAuthorized(boolean authorized) {
    this.authorized = authorized;
  }

  public boolean getAuthorized() {
    return authorized;
  }

  public void setMovementRef(UUID movementRef) {
    this.movementRef = movementRef;
  }

  public Optional<UUID> getMovementRef() {
    return Optional.ofNullable(movementRef);
  }

  public String getCurrency() {
    return this.currency;
  }
}
