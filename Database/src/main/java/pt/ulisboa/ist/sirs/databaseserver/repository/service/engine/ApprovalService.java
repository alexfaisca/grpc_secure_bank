package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine;

import pt.ulisboa.ist.sirs.databaseserver.domain.Approval;
import pt.ulisboa.ist.sirs.databaseserver.dto.ApprovalDto;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl.ApprovalDAO;

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
