package pt.tecnico.sirs.utils.exceptions;

public class TamperedMessageException extends RuntimeException {
  public TamperedMessageException() {
    super("Message contents were tampered with");
  }
}
