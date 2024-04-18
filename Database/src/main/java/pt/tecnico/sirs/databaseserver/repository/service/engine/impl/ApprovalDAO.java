package pt.tecnico.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;
import pt.tecnico.sirs.databaseserver.domain.Approval;

import java.util.List;
import java.util.UUID;

public class ApprovalDAO extends AbstractDAO<Approval, Long> {
  public ApprovalDAO(SessionFactory sessionFactory) {
    super(sessionFactory);
  }

  public List<Approval> getApprovalsByPaymentRef(UUID paymentRef) {
    return sessionFactory.getCurrentSession()
        .createQuery(
            "FROM " + Approval.class.getSimpleName() + " a WHERE a.paymentRef=:paymentRef", Approval.class)
        .setParameter("paymentRef", paymentRef)
        .list();
  }
}
