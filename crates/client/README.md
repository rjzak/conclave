## Conclave Client
Client application and library for Conclave.

### `conclave://` links
A link such as `conclave://chat.example.com:9123` opens the client's login
window for that server, with nothing sent until you choose to connect. The
port may be left off for the default, an IPv6 address goes in brackets
(`conclave://[::1]:9123`). A link may carry a user name, and a password with
it, to fill in the login window: `conclave://ada:secret@chat.example.com`.
Percent-encode any `:`, `@` or `/` in them. Even then the client waits for you
to connect, and keeps the password out of its logs. Bear in mind that a link
with a password in it shows that password to anyone who sees the link.

The client also takes a link on the command line:

```sh
conclave-client conclave://localhost:9123
```

For a clicked link to reach the client, the operating system has to know the
client handles them:

- **macOS**: the app bundle built by `macos/bundle.sh` declares the scheme, and
  Launch Services registers it the first time the app is opened. A link opened
  while the client is running goes to the running client.
- **Linux**: install `linux/conclave-client.desktop` and make it the handler,
  with `conclave-client` on your `PATH`:

  ```sh
  install -Dm644 linux/conclave-client.desktop ~/.local/share/applications/conclave-client.desktop
  xdg-mime default conclave-client.desktop x-scheme-handler/conclave
  ```

- **Windows**: a release build of the client registers the scheme for the
  current user when it starts, under `HKEY_CURRENT_USER\Software\Classes`, so
  no administrator rights are needed. It leaves alone a registration whose
  program still exists, even another program's, and replaces one whose program
  has gone. Debug builds never register themselves; to test links with one,
  register it by hand:

  ```text
  reg add HKCU\Software\Classes\conclave /ve /d "URL:Conclave" /f
  reg add HKCU\Software\Classes\conclave /v "URL Protocol" /d "" /f
  reg add HKCU\Software\Classes\conclave\shell\open\command /ve /d "\"C:\path\to\conclave-client.exe\" \"%1\"" /f
  ```

On Linux and Windows each clicked link starts a new copy of the client.
