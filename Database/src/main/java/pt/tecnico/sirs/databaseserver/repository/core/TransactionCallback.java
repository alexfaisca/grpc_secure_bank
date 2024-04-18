package pt.tecnico.sirs.databaseserver.repository.core;

interface TransactionCallback {
  void doInTransaction();
}
