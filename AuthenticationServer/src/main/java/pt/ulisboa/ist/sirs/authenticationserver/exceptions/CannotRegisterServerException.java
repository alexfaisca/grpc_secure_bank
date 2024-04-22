package pt.ulisboa.ist.sirs.authenticationserver.exceptions;

public class CannotRegisterServerException extends Exception {
    public CannotRegisterServerException(String service, String address) {
        super("Cannot register server at '" + address + "' as service '" + service + "'");
    }
    public CannotRegisterServerException(String service, String address, String qualifier) {
        super("Server at '" + address + "' with qualifier '" + qualifier + "' already registered as service '" + service + "'");
    }
}

