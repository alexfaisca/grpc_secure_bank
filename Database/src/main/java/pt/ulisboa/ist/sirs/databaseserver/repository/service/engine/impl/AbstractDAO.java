package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl;

import org.hibernate.SessionFactory;

import java.io.Serializable;
import java.lang.reflect.ParameterizedType;

abstract class AbstractDAO<T extends Serializable, Id extends Serializable> implements AbstractMinimalSpecDAO<T, Id> {
  protected final SessionFactory sessionFactory;
  private final Class<Id> idClass;

  public AbstractDAO(SessionFactory sessionFactory) {
    this.idClass = (Class<Id>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[1];
    this.sessionFactory = sessionFactory;
  }

  @Override
  public Id save(T entity) {
    return idClass.cast(sessionFactory.getCurrentSession().save(entity));
  }

  @Override
  public void delete(T object) {
    sessionFactory.getCurrentSession().delete(object);
  }
}
