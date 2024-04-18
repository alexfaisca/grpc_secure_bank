package pt.tecnico.sirs.databaseserver.repository.service.engine;

import pt.tecnico.sirs.databaseserver.domain.Approval;
import pt.tecnico.sirs.databaseserver.dto.ApprovalDto;
import pt.tecnico.sirs.databaseserver.repository.service.engine.impl.ApprovalDAO;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public class ApprovalService {
  private final ApprovalDAO approvalDAO;

  public ApprovalService(ApprovalDAO approvalDAO) {
    this.approvalDAO = approvalDAO;
  }

  private static ApprovalDto toDto(Approval approval) {
    return new ApprovalDto(approval.getHolder(), approval.getPaymentRef(), approval.getApprovalDate());
  }

  public ApprovalDto addPaymentApproval(UUID paymentRef, UUID holder, LocalDateTime date) {
    Approval newApproval = new Approval(holder, paymentRef, date);
    newApproval.setId(approvalDAO.save(newApproval));
    return toDto(newApproval);
  }

  public List<ApprovalDto> getPaymentApprovals(UUID paymentRef) {
    return approvalDAO.getApprovalsByPaymentRef(paymentRef).stream().map(ApprovalService::toDto).toList();
  }
}
