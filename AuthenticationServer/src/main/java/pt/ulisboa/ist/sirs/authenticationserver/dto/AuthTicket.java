package pt.ulisboa.ist.sirs.authenticationserver.dto;

import java.time.OffsetDateTime;

public record AuthTicket(String qualifier, String address, Integer port, OffsetDateTime timeStamp, byte[] sessionKey, byte[] sessionIV, byte[] ticket) {
}
