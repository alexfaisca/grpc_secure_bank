package pt.ulisboa.ist.sirs.databaseserver.repository.service.engine;

import pt.ulisboa.ist.sirs.databaseserver.domain.BankAccountHolder;
import pt.ulisboa.ist.sirs.databaseserver.dto.HolderDto;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl.BankAccountHolderDAO;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class BankAccountHolderService {
    private final BankAccountHolderDAO bankAccountHolderDAO;

    public BankAccountHolderService(BankAccountHolderDAO bankAccountHolderDAO) {
        this.bankAccountHolderDAO = bankAccountHolderDAO;
    }

    private static HolderDto toDto(BankAccountHolder holder) {
        return new HolderDto(holder.getName(), holder.getAccountNumber(), holder.getNumber());
    }

    public HolderDto addHolder(String name, UUID accountNumber) {
        BankAccountHolder holder = new BankAccountHolder(name, accountNumber);
        holder.setId(bankAccountHolderDAO.save(holder));
        return toDto(holder);
    }

    public boolean checkExists(String name) {
        return bankAccountHolderDAO.checkExists(name);
    }

    public Optional<HolderDto> getHolderByName(String name) {
        return bankAccountHolderDAO.findByName(name).map(BankAccountHolderService::toDto);
    }

    public List<HolderDto> getHolderByAccountNumber(UUID accountNumber) {
        return bankAccountHolderDAO.findByAccountNumber(accountNumber).stream().map(BankAccountHolderService::toDto).toList();
    }

    public void deleteHolderByAccountNumber(UUID accountNumber) {
        List<BankAccountHolder> holders = bankAccountHolderDAO.findByAccountNumber(accountNumber);
        holders.forEach(bankAccountHolderDAO::delete);
    }
}
