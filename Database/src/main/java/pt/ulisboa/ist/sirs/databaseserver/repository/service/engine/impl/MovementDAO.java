package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;
import pt.ulisboa.ist.sirs.databaseserver.domain.Movement;

import java.util.List;
import java.util.UUID;

public final class MovementDAO extends AbstractDAO<Movement, Long> {

  public MovementDAO(SessionFactory sessionFactory) {
    super(sessionFactory);
  }

  public List<Movement> findByAccountFrom(UUID number) {
    return sessionFactory.getCurrentSession()
        .createQuery(
            "FROM " + Movement.class.getSimpleName() + " m WHERE m.accountFrom=:account", Movement.class)
        .setParameter("account", number)
        .list();
  }

  public List<Movement> findByAccountTo(UUID number) {
    return sessionFactory.getCurrentSession()
        .createQuery(
            "FROM " + Movement.class.getSimpleName() + " m WHERE m.accountTo=:account", Movement.class)
        .setParameter("account", number)
        .list();
  }
}
