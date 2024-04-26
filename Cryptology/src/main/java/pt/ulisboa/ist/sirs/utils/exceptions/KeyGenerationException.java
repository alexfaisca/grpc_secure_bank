package pt.ulisboa.ist.sirs.utils.exceptions;

public class KeyGenerationException extends RuntimeException {
  public KeyGenerationException() {
    super("Key generation went wrong.");
  }
}
