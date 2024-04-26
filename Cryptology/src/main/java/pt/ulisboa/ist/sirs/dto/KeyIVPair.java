package pt.ulisboa.ist.sirs.dto;

import javax.crypto.SecretKey;

public record KeyIVPair(SecretKey key, byte[] iv) {
}
