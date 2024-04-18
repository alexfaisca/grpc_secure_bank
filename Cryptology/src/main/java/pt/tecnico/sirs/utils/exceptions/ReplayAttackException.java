package pt.tecnico.sirs.utils.exceptions;

public class ReplayAttackException extends RuntimeException {
  public ReplayAttackException() {
    super("Warning! Replay attack detected!");
  }
}
