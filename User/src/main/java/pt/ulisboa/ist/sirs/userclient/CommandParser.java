package pt.ulisboa.ist.sirs.userclient;

import pt.ulisboa.ist.sirs.userclient.grpc.UserService;
import pt.ulisboa.ist.sirs.userclient.tools.SecureDocument;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class CommandParser {
  private static final String COMMAND_SPLITTER = " ";
  private static final String CREATE_ACCOUNT = "createAccount";
  private static final String DELETE_ACCOUNT = "deleteAccount";
  private static final String BALANCE = "balance";
  private static final String SHOW_EXPENSES = "getMovements";
  private static final String HELP = "help";
  private static final String PROTECT = "protect";
  private static final String CHECK = "check";
  private static final String UNPROTECT = "unprotect";
  private static final String PAYMENT_ORDER = "orderPayment";
  private static final String EXIT = "exit";

  private final UserService userService;
  private final SecureDocument crypto;

  public CommandParser(UserService userService, SecureDocument crypto) {
    this.userService = userService;
    this.crypto = crypto;
  }

  public void parseInput() {
    boolean exit = false;
    try (Scanner scanner = new Scanner(System.in)) {
      while (!exit) {

        System.out.print("> ");
        String line = scanner.nextLine().trim();
        String[] command = line.split(COMMAND_SPLITTER);

        switch (command[0]) {
          case CREATE_ACCOUNT -> this.createAccount(command);
          case DELETE_ACCOUNT -> this.deleteAccount(command);
          case BALANCE -> this.balance(command);
          case SHOW_EXPENSES -> this.getMovements(command);
          case PAYMENT_ORDER -> this.orderPayment(command);
          case PROTECT -> this.protect(command);
          case CHECK -> this.check(command);
          case UNPROTECT -> this.unprotect(command);
          case HELP -> this.printUsage();
          case EXIT -> exit = true;
          default -> {
            System.out.println("Bad command!\n");
            this.printUsage();
          }
        }
      }
    }
  }

  private void createAccount(String[] command) {
    if (command.length < 3) {
      this.printUsage();
      return;
    }

    List<String> usernames = new ArrayList<>(Arrays.asList(command).subList(1, command.length - 1));
    List<String> passwords = new ArrayList<>();
    passwords.add(command[command.length - 1]);
    this.userService.createAccount(usernames, passwords, OffsetDateTime.now().toString());
  }

  private void deleteAccount(String[] command) {
    if (command.length != 3) {
      this.printUsage();
      return;
    }

    String username = command[1];
    String password = command[2];
    this.userService.deleteAccount(username, password, OffsetDateTime.now().toString());
  }

  private void balance(String[] command) {
    if (command.length != 3) {
      this.printUsage();
      return;
    }

    String username = command[1];
    String password = command[2];
    this.userService.balance(username, password, OffsetDateTime.now().toString());
  }

  private void getMovements(String[] command) {
    if (command.length != 3) {
      this.printUsage();
      return;
    }

    String username = command[1];
    String password = command[2];
    this.userService.getMovements(username, password, OffsetDateTime.now().toString());
  }

  private void orderPayment(String[] command) {
    if (command.length < 6) {
      this.printUsage();
      return;
    }

    String username = command[1];
    String password = command[2];
    String amount = command[3];
    String recipient = command[4];
    String description = String.join(" ", new ArrayList<>(Arrays.asList(command).subList(5, command.length)));
    this.userService.paymentOrder(username, password, LocalDateTime.now().toString(), amount, description, recipient, OffsetDateTime.now().toString());
  }

  private void protect(String[] command) {
    if (command.length != 3) {
      this.printUsage();
      return;
    }

    String inputFile = command[1];
    String outputFile = command[2];
    this.crypto.protect(inputFile, outputFile);
  }

  private void check(String[] command) {
    if (command.length != 2) {
      this.printUsage();
      return;
    }

    String inputFile = command[1];
    System.out.println(this.crypto.check(inputFile) ? "Check successful!\n" : "Check unsuccessful!\n");
  }

  private void unprotect(String[] command) {
    if (command.length != 3) {
      this.printUsage();
      return;
    }

    String inputFile = command[1];
    String outputFile = command[2];
    this.crypto.unprotect(inputFile, outputFile);
  }

  private void printUsage() {
    System.out.println("""
      Usage:
      - createAccount (<username> <password>)*
      - deleteAccount <username> <password>
      - balance <username> <password>
      - getMovements <username> <password>
      - orderPayment <username> <password> <amount> <recipient> <description>
      - protect <input_file> <output_file>
      - check <input_file>
      - unprotect <input_file> <output_file>
      - help
      - exit
      Notes: (1) Each username is unique and is linked to only one account.
             (2) To process payments in accounts with multiple holders they all must place exactly the same order first.
      """);
  }
}