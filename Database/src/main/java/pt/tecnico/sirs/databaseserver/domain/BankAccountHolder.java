package pt.tecnico.sirs.databaseserver.domain;

import javax.persistence.*;

import org.hibernate.annotations.ColumnTransformer;

import java.io.Serializable;
import java.util.UUID;

@Entity
public class BankAccountHolder implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          id,
          'holder'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'holder'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private long id;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          name,
          'holder'
      )
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'holder'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private String name;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          accountNumber,
          'holder'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'holder'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private UUID accountNumber;

  @JoinColumn
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
          number,
          'holder'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
          ?::text,
          'holder'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private UUID number;

  public BankAccountHolder() {
  }

  public BankAccountHolder(String holder, UUID accountNumber) {
    this.number = UUID.randomUUID();
    this.accountNumber = accountNumber;
    this.name = holder;
  }

  public void setId(long id) {
    this.id = id;
  }

  public long getId() {
    return id;
  }

  public UUID getAccountNumber() {
    return accountNumber;
  }

  public String getName() {
    return name;
  }

  public UUID getNumber() {
    return number;
  }
}
