package pt.ulisboa.ist.sirs.utils.exceptions;

public class TamperedMessageException extends RuntimeException {
  public TamperedMessageException() {
    super("Message contents were tampered with");
  }
}
