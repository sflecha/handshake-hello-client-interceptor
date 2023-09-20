## About The Project

The goal of the project is to implement an https service capable of reading tls extensions and processing them in the logic layer.

To implement it, we have used Spring Boot Web-flux (v3) which provides a netty server and an api for the connector that provides tools to facilitate the solution of this task.

### Prerequisites
* Maven
* Java 17
* Private key and certificate for the server

### Usage
* Configure TLS server in the Spring Boot application.yml
```
server:
  ssl:
    enabled: true
    certificate-private-key: privkey.pem
    certificate: fullchain.pem
```
* Run
```
mvn spring-boot:run
```

#### Useful debug java options
* -Djavax.net.debug=ssl:handshake

