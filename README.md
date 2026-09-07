[![Test](https://github.com/rjzak/conclave/actions/workflows/ci.yml/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/ci.yml)
[![Release](https://github.com/rjzak/conclave/actions/workflows/release.yml/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/release.yml)
[![CodeQL](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql)
![GitHub License](https://img.shields.io/github/license/rjzak/conclave)

## Conclave

This is a work-in-progress effort to make a modern version of [Carracho](https://www.carracho.com) or Hotline to enable communities to have control over their data.

### Components

* Client: a client connects to a server:
  * directly,
  * via DNS [service record](https://www.cloudflare.com/learning/dns/dns-records/dns-srv-record/),
  * via local discovery ([mDNS](https://en.wikipedia.org/wiki/Multicast_DNS)), or 
  * via a tracker.
* Server: a server accepts connections from a client and optionally advertises itself to one or more trackers.
* Tracker: a tracker receives information from servers and relays it to clients.
* The tracker and server may be graphical desktop applications (`--features=gui`) which have "gui" in the file name in
  releases or background system processes (command line).

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

* A user connects to the server in a variety of ways (see above)
* Server administration via the client if authenticated
* Ephemeral group chats
* Direct messages (end-to-end encrypted)
* File sharing
* Message boards

## AI Disclosure

Portions of this project have been developed with the assistance of AI tools, mostly around the graphical interface. Nothing has been committed without human review and testing.
