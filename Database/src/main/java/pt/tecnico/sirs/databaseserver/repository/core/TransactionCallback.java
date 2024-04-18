package pt.tecnico.sirs.databaseserver.repository.core;

interface TransactionCallback {
  void beforeOperation();

  void doInTransaction();

  void afterOperation();
}
