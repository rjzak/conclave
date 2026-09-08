## Initial Roadmap for Conclave Development

### Phase 0
- [X] Basic encrypted networking.
- [X] Unit tests showing basic functionality works.
- [X] Create a basic Client, Server, Tracker.
- [X] Create a basic Client GUI.
- [X] Client can connect to Tracker, list Servers, and connect to Server.
- [X] Client can see other users, and see when a user joins or leaves.

### Phase 1
- [X] Add chatroom functionality.
- [X] Add direct message functionality.
- [X] Add server administration functionality.
- [X] Show users: status, group memberships (roles), administrator status.

### Phase 2
- [X] Add forums.
- [X] Add file sharing and permissions for shared files and filesystem.
- [ ] Add support for `conclave://` links.
- [ ] Add optional forum content expiration.
- [ ] Add forum search functionality.

### Phase 3
- [ ] Add rich text support, possibly including graphics.
- [ ] Add reactions to:
  - [ ] forums
  - [ ] chat
  - [ ] determine the type of reaction: emoji, custom image, something else?

## Possible Future Features
- [ ] Web-based client, possibly using WebAssembly.
- [ ] Mobile client.
- [ ] Audio/Video sharing.
  - [ ] Streaming.
  - [ ] Audio chat.
  - [ ] Video chat.
- [ ] End-to-end encryption for:
  - [X] direct messages
  - [ ] chat
  - [ ] forums
  - [ ] everything else.
- [ ] Plugin systems for servers, clients; possibly using WebAssembly.
- [ ] Python client module for bots and other automation.
