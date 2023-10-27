# Thought processes

* Translation – how to take known patterns and translate them to Rust?
* Start with the domain:
  * Drives all other code.
  * Requires few external crates.
  * Rust shines in parsing domain models and handling errors.
* Implement domain models: need key types to work with.
  * Consider lifetimes of string newtypes. Is it likely the reference will stick around as long as the type?
  * Do we need mutability?
  * Consider basic trait implementations. It's helpful for us to treat a username as a string (e.g. for interfacing
    with a DB), but we don't want strings to be treated as usernames.
  * How to we ensure users cannot manipulate the internal representation of a type?
  * How do we ensure the type is always valid?
  * Error handling? How to we create a limited set of domain errors that we can guarantee are the only errors that
    will returned?
  * new_unchecked: how to avoid abuse?
* Errors
  * Style decision: full sentences except for fragments. Helps structuring more complex error messages.
  * How detailed can we be with error messages? E.g. collecting all invalid chars rather than terminating on the first
    one. Who is the audience? What do they need to know?
