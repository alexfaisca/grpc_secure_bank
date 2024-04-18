package pt.tecnico.sirs.databaseserver.domain;

import org.hibernate.annotations.ColumnTransformer;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
public class Approval implements Serializable {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @ColumnTransformer(read = """
      pgp_sym_decrypt(
      id,
      'approval'
      )
      """, write = """
      pgp_sym_encrypt(
      ?::text,
      'approval'
      )
      """)
  @Column(unique = true, nullable = false, columnDefinition = "bytea")
  private long id;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
      holder,
      'approval'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
      ?::text,
      'approval'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private UUID holder;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
      paymentRef,
      'approval'
      )::uuid
      """, write = """
      pgp_sym_encrypt(
      ?::text,
      'approval'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private UUID paymentRef;

  @ColumnTransformer(read = """
      pgp_sym_decrypt(
      approvalDate,
      'approval'
      )
      """, write = """
      pgp_sym_encrypt(
      ?::text,
      'approval'
      )
      """)
  @Column(nullable = false, columnDefinition = "bytea")
  private LocalDateTime approvalDate;

  public Approval() {
  }

  public Approval(UUID holder, UUID reference, LocalDateTime date) {
    this.holder = holder;
    this.paymentRef = reference;
    this.approvalDate = date;
  }

  public void setId(long id) {
    this.id = id;
  }

  public long getId() {
    return id;
  }

  public UUID getHolder() {
    return holder;
  }

  public UUID getPaymentRef() {
    return paymentRef;
  }

  public LocalDateTime getApprovalDate() {
    return approvalDate;
  }
}
