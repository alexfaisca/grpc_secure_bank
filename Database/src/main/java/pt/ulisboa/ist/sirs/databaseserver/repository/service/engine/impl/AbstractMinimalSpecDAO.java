package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl;

import java.io.Serializable;

interface AbstractMinimalSpecDAO<PersistenceObject extends Serializable, PersistenceObjectId extends Serializable> {
  PersistenceObjectId save(PersistenceObject object);

  void delete(PersistenceObject object);
}
