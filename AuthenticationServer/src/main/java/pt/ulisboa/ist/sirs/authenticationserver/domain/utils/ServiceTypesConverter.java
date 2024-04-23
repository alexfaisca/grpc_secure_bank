package pt.ulisboa.ist.sirs.authenticationserver.domain.utils;

import pt.ulisboa.ist.sirs.authenticationserver.exceptions.NoSuchServiceException;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.Services;
import pt.ulisboa.ist.sirs.authenticationserver.enums.Service.Types;

public final class ServiceTypesConverter {
  public static Types convert(Services s) throws NoSuchServiceException {
    switch (s.getNumber()) {
      case Services.AuthServer_VALUE -> {return Types.AuthServer;}
      case Services.DatabaseServer_VALUE -> {return Types.DatabaseServer;}
      default -> {
        throw new NoSuchServiceException(s.name());
      }
    }
  }
}
