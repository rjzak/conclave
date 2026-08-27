## Conclave Server
Server application and library for Conclave.

On first run, the configuration file will be created at:
* `~/.config/conclave/server.toml`
* Or `C:\Users\USER_NAME\AppData\Local\Conclave\server.toml` on Windows.

The following required fields will be created on first launch:
* `ip`: By default, this will be "127.0.0.1". Change to "0.0.0.0" to listen on all IP addresses and allow external connections. This may instead be an IPv6 address, but only one (IPv4 or IPv6) can be specified.
* `port`: By default, this will be "9123". Anything above "1024" can be used with requiring admin rights. The highest is "65535".

Add or edit these optional fields if desired:
* `domain`: Specify an advertised domain for clients to use instead of an IP address.
* `mdns`: Enable multicast DNS support for automatic discovery on your local network.
* `share`: A directory for optional file sharing.
