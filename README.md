# SecureBank Project Read Me

A distributed bank application that supports user authentication through the Needham-Schroeder protocol, using Diffie-Hellman key distribution between the user and authentication server, and communication in HTTP/2 through gRPC with multiple client concurrent support and key management, sporting a custom database managemer system built with hibernate.

Checkout the demo video to see it all coming together!

## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

## Installation

To see the project in action, it might be necessary to setup a virtual environment, with (3) networks and 4 machines, or let it be performed automatically by maven
by running with the default settings as exemplified bellow in only one machine capable of simulating the other 4.

A visual diagram of the machines is available in the report, where only the cryptology module is not a machine.

### Prerequisites

```sh
$ psql -h localhost -U postgres
```

```sh
> CREATE DATABASE blingbank;
```

```sh
> CREATE USER bling WITH PASSWORD 'sirs-encrypt';
```

```sh
> \c blingbank
```

```sh
> CREATE EXTENSION IF NOT EXISTS pgcrypto;
```


#### Machine 1 - User

This machine runs Java 17, Maven 3.9 and PostgreSQL 16.1.

To initialize:

```sh
$ mvn clean install
```

To run:

```sh
$ mvn exec:exec
```

Available commands:

```sh
> createAccount (<username> <password>)*
```

```sh
> deleteAccount <username> <password>
```

```sh
> balance <username> <password>
```

```sh
> getMovements <username> <password>
```

```sh
> addExpense <username> <password> <amount> <description>
```

```sh
> orderPayment <username> <password> <amount> <recipient> <description>
```

```sh
> protect <input_file> <output_file>
```

```sh
> check <input_file>
```

```sh
> unprotect <input_file> <output_file>
```

```sh
> help
```

```sh
> exit
```

(1) Each username is unique and is linked to only one account.
(2) To process payments in accounts with multiple holders they all must place exactly the same order first.

All attacks on the system are promptly outputed to the terminal, resulting in the throw of an expection.

#### Machine 2 - Bank

This machine runs Java 17, Maven 3.9 and PostgreSQL 16.1.

To initialize:

```sh
$ mvn clean install
```

To run:

```sh
$ mvn exec:exec
```

#### Machine 2 - Database

This machine runs Java 17, Maven 3.9 and PostgreSQL 16.1.

To initialize:

```sh
$ mvn clean install
```

To run:

```sh
$ mvn exec:exec
```

All attacks on the system are promptly outputed to the terminal, resulting in the throw of an expection.

#### Machine 4 - Authentication Server

This machine runs Java 17, Maven 3.9 and PostgreSQL 16.1.

To initialize:

```sh
$ mvn clean install
```

To run:

```sh
$ mvn exec:exec
```

## Demonstration

Now that all the networks and machines are up and running, we present here a recorded demonstration of our project:
- [Demo](https://drive.tecnico.ulisboa.pt/download/570023764850777)

## Additional Information

### Links to Used Tools and Libraries

- [Java 17](https://openjdk.java.net/)
- [Maven 3.9.6](https://maven.apache.org/)
- [PostgreSQL 16.1](https://www.postgresql.org/about/news/postgresql-161-155-1410-1313-1217-and-1122-released-2749/)

### Versioning

We use [SemVer](http://semver.org/) for versioning.  

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.

----
END OF README
