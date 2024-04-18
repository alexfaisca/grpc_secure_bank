package pt.tecnico.sirs.databaseserver.repository.core;

import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.cfg.Configuration;

public final class HibernateUtil {
  private static SessionFactory sessionFactory = buildSessionFactory();

  private static SessionFactory buildSessionFactory() {
    try {
      if (sessionFactory == null) {
        sessionFactory = new Configuration().configure("hibernate.cfg.xml").buildSessionFactory();
      }
      return sessionFactory;
    } catch (Throwable ex) {
      throw new ExceptionInInitializerError(ex);
    }
  }

  public static SessionFactory getSessionFactory() {
    return sessionFactory;
  }

  public static void shutdown() {
    getSessionFactory().close();
  }

  static void inTransaction(TransactionCallback transactionCallback) {
    Transaction transaction = HibernateUtil.getSessionFactory().getCurrentSession().getTransaction();
    if (!HibernateUtil.getSessionFactory().getCurrentSession().getTransaction().isActive()) {
      transaction.begin();
      try {
        transactionCallback.doInTransaction();
        transaction.commit();
      } catch (Exception e) {
        transaction.rollback();
        throw e;
      }
    } else
      transactionCallback.doInTransaction();
  }
}
