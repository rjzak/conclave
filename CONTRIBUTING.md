## Conclave Contributing Guidelines

Contributions welcome!

> [!TIP]
> Before spending lots of time on something, ask for feedback on your idea first!

### Installing and Contributing
* Install [Rust](https://rust-lang.org/tools/install/), it's recommended to install from the official website.
* Fork the repository.
* Clone your fork locally.
* Create a new branch where you'll make changes. `git checkout -b <branch-name>`
  * Making a new branch allows for keeping `main` in-sync with the upstream repository.
  * This also allows for multiple PRs to be made from the same fork.
* Work on changes in this branch.
* Commit and push your changes.
  * Multiple commits can be used to break up a PR into smaller, logical pieces.
  * Squash commits if the commits are just iterative changes, not logically distinct.
  * The various commits should tell a story for the project as a whole!
* Make a pull request.
  * To be easily understood, pull requests should be small and focused on a single feature or bug fix.
  * Use multiple PRs (different branches) from the same fork to implement different features or bug fixes.
* Keep the new PR as a draft until it's ready for review.

### Testing and Linting
* Run `cargo test` to ensure all tests pass.
* Run `cargo clippy` for code quality checks.

### Code Style
We use the standard Rust code style, so run `cargo fmt` to format your code before committing.
