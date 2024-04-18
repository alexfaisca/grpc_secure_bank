package pt.tecnico.sirs.databaseserver.domain;

import javax.persistence.*;

import org.hibernate.annotations.ColumnTransformer;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.*;

@Entity
public class BankAccount implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          id,
          'account'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'account'
      )
      """)
  @Column(columnDefinition = "bytea")
  private long id;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          number,
          'account'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'account'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private UUID number;

  @ColumnTransformer(read = """
      pgp_sym_decrypt_bytea(
          passwords,
          'account'
      )
      """, write = """
      pgp_sym_encrypt_bytea(
          ?,
          'account'
      )
      """)
  @Column(columnDefinition = "bytea")
  private byte[] passwords;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          balance,
          'account'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'account'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private BigDecimal balance;

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

  public BankAccount(byte[] passwords, BigDecimal initialDeposit) {
    this.number = UUID.randomUUID();
    this.passwords = passwords;
    this.balance = initialDeposit;
    this.currency = "EUR";
  }

  public BankAccount() {
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public byte[] getPassword() {
    return passwords;
  }

  public UUID getNumber() {
    return this.number;
  }

  public BigDecimal getBalance() {
    return this.balance;
  }

  public String getCurrency() {
    return this.currency;
  }

  public void moveBalance(BigDecimal amount) {
    balance = balance.add(amount);
  }
}
