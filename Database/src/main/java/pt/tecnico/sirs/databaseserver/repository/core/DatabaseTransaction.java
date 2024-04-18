package pt.tecnico.sirs.databaseserver.repository.core;

public abstract class DatabaseTransaction implements TransactionCallback {
  protected final void execute() {
    HibernateUtil.inTransaction(this);
  }

  @Override
  public void beforeOperation() {
  }

  @Override
  public abstract void doInTransaction();

  @Override
  public void afterOperation() {
  }
}
