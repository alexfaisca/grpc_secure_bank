package pt.ulisboa.ist.sirs.authenticationserver.dto;

public record TargetServer(String server, String address, Integer port, String qualifier) {
}
