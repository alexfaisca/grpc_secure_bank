package pt.ulisboa.ist.sirs.databaseserver.repository.core;

interface TransactionCallback {
  void beforeOperation();

  void doInTransaction();

  void afterOperation();
}
