[![Test](https://github.com/rjzak/conclave/actions/workflows/ci.yml/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/ci.yml)
[![Release](https://github.com/rjzak/conclave/actions/workflows/release.yml/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/release.yml)
[![CodeQL](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/rjzak/conclave/actions/workflows/github-code-scanning/codeql)
![GitHub License](https://img.shields.io/github/license/rjzak/conclave)

## Conclave

This is an opinionated work-in-progress effort to make a modern version of [Carracho](https://www.carracho.com) or Hotline to enable communities
to have control over their data.

> [!IMPORTANT]
> This project is in active development, and alpha versions of Conclave which have been released aren't compatible with
> each other, and the latest releases are not compatible with the latest code in the repository. The protocol will be
> stabilized before a beta release.

### Components
The Conclave ecosystem consists of three components:

* Client: a client connects to a server:
  * directly,
  * via DNS [service record](https://www.cloudflare.com/learning/dns/dns-records/dns-srv-record/),
  * via local discovery ([mDNS](https://en.wikipedia.org/wiki/Multicast_DNS)), or 
  * via a Tracker.
* Server: a server accepts connections from a client and optionally advertises itself to one or more trackers.
* Tracker: a tracker receives information from servers and relays it to clients.

The tracker and server may be graphical desktop applications (`--features=gui`) which have "gui" in the file name in
  releases or background system processes (command line). The tracker and server are also available as Debian packages.

### Internal Features

* Cryptography:
  * Trackers have a private key. It shares its public key and signs server advertisements sent to clients. Tracker communications aren't encrypted.
  * Clients keep a list of trackers and their signatures; the user is alerted if the signature does not match. This is designed to mimic the behaviour of SSH. Clients have public/private keys.
  * Servers have a public/private keys. Clients and servers renegotiate the key periodically. An identifying key is generated on the first run, and this is shared with the client to also mimic the behaviour of SSH.
  * PQC: Servers and clients use ML-KEM-1024 for key negotiation, trackers sign data with ML-DSA-87.
* Administration:
  * On the first run, the server generates a password for the administrator ("admin") user, which can be changed on the command line.
  * Users may be an administrator, and may use the client to manage the settings of the server.
    * Creating/Editing/Deleting user accounts.
    * Enabling/Disabling anonymous client connections or set optional maximum amount of connected users.
    * Adding/Removing trackers.
    * Enable/Disable chats, message boards
    * Specify role-based access controls for chats, forums, shared files.

### User Features

* A user connects to the server in a variety of ways (see above)
* Server administration via the client, if authenticated and authorised.
* **Ephemeral** group chats
* **Ephemeral** direct messages, end-to-end encrypted
* File sharing
* Message boards; any permanent message should be under a message board topic.

## AI Disclosure

Portions of this project have been developed with the assistance of AI tools, mostly around the graphical interface. Nothing has been committed without human review and testing.
