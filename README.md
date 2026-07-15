[![Test](https://github.com/rjzak/conclave/actions/workflows/ci.yml/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql)
![GitHub License](https://img.shields.io/github/license/rjzak/conclave)

## Conclave

This is a work-in-progress effort to make a modern version of [Carracho](https://www.carracho.com) or Hotline to enable communities to have control over their data.

### Components

* Client: a client connects to a server, either directly, via local discovery, or via finding it from a tracker.
* Server: a server accepts connections from a client and optionally advertises itself to one or more trackers.
* Tracker: a tracker receives information from servers and relays it to clients.

### Internal Features

* Cryptography:
  * Trackers have a private key. It shares its public key and signs server advertisements sent to clients.
  * Clients keep a list of trackers and their signatures; the user is alerted if the signature does not match. This is designed to mimic the behaviour of SSH.
  * Servers have a private key, which is shared with clients. Clients and servers renegotiate the key periodically. An identifying key is generated on the first run, and this is shared with the client to also mimic the behaviour of SSH.
* Administration:
  * On the first run, the server generates a password for the administrator ("admin") user, which can be changed on the command line.
  * Users may be an administrator, and may use the client to manage the settings of the server.
    * Creating/Editing/Deleting user accounts.
    * Enabling/Disabling anonymous client connections.
    * Adding/Removing trackers.

### User Features

* A user may connect to the server: directly, via bookmark, via local discovery, via tracker, or via a DNS SRV record.
* Administration via the client
* Group chats
* Direct messages (end-to-end encrypted)
* File sharing
* Message boards

## AI Disclosure

Portions of this project have been developed with the assistance of AI tools, mostly around the graphical interface. Nothing has been committed without human review and testing.
