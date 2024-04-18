package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;
import pt.ulisboa.ist.sirs.databaseserver.domain.Payment;

import javax.persistence.NoResultException;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;

public class PaymentDAO extends AbstractDAO<Payment, Long> implements Serializable {
  public PaymentDAO(SessionFactory sessionFactory) {
    super(sessionFactory);
  }

  public Optional<Payment> getPaymentByAccountFromAndAccountToAndAmountAndDescription(UUID accountFrom, UUID accountTo,
      BigDecimal amount, String description) {
    try {
      return Optional.ofNullable(
          sessionFactory.getCurrentSession()
              .createQuery("FROM " + Payment.class.getSimpleName() + " p " +
                  "WHERE p.accountFrom=:accountFrom " +
                  "AND p.accountTo=:accountTo " +
                  "AND p.amount=:amount " +
                  "AND p.description=:description", Payment.class)
              .setParameter("accountFrom", accountFrom)
              .setParameter("accountTo", accountTo)
              .setParameter("amount", amount)
              .setParameter("description", description)
              .getSingleResult());
    } catch (NoResultException e) {
      return Optional.empty();
    }
  }
}
