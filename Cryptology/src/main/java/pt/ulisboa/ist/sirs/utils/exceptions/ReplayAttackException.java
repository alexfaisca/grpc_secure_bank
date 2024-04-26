package pt.ulisboa.ist.sirs.utils.exceptions;

public class ReplayAttackException extends RuntimeException {
  public ReplayAttackException() {
    super("Replay attack detected.");
  }
}
