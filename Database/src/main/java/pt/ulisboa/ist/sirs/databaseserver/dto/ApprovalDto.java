package pt.ulisboa.ist.sirs.databaseserver.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record ApprovalDto(UUID holder, UUID paymentRef, LocalDateTime approvalDate) {
}
