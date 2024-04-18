package pt.tecnico.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;
import pt.tecnico.sirs.databaseserver.domain.BankAccountHolder;

import javax.persistence.NoResultException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class BankAccountHolderDAO extends AbstractDAO<BankAccountHolder, Long> {

  public BankAccountHolderDAO(SessionFactory sessionFactory) {
    super(sessionFactory);
  }

  public Optional<BankAccountHolder> findByName(String name) {
    try {
      return Optional.ofNullable(
          sessionFactory.getCurrentSession()
              .createQuery("FROM " + BankAccountHolder.class.getSimpleName() + " a WHERE a.name=:name",
                  BankAccountHolder.class)
              .setParameter("name", name)
              .getSingleResult());
    } catch (NoResultException e) {
      return Optional.empty();
    }
  }

  public boolean checkExists(String name) {
    try {
      Optional<BankAccountHolder> holder = Optional.ofNullable(
          sessionFactory.getCurrentSession()
              .createQuery("FROM " + BankAccountHolder.class.getSimpleName() + " a WHERE a.name=:name",
                  BankAccountHolder.class)
              .setParameter("name", name)
              .getSingleResult());
      return holder.isPresent();
    } catch (NoResultException e) {
      return false;
    }
  }

  public List<BankAccountHolder> findByAccountNumber(UUID accountNumber) {
    return sessionFactory.getCurrentSession()
        .createQuery("FROM " + BankAccountHolder.class.getSimpleName() + " h WHERE h.accountNumber=:accountNumber",
            BankAccountHolder.class)
        .setParameter("accountNumber", accountNumber)
        .list();
  }
}
