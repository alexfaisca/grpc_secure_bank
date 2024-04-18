package pt.tecnico.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;
import pt.tecnico.sirs.databaseserver.domain.BankAccount;

import javax.persistence.NoResultException;
import java.util.Optional;
import java.util.UUID;

public final class BankAccountDAO extends AbstractDAO<BankAccount, Long> {

  public BankAccountDAO(SessionFactory sessionFactory) {
    super(sessionFactory);
  }

  public Optional<BankAccount> findByNumber(UUID number) {
    try {
      return Optional.ofNullable(sessionFactory.getCurrentSession()
          .createQuery("FROM " + BankAccount.class.getSimpleName() + " h WHERE h.number=:number", BankAccount.class)
          .setParameter("number", number)
          .getSingleResult());
    } catch (NoResultException e) {
      return Optional.empty();
    }
  }
}
