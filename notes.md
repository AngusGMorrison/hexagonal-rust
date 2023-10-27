# Thought processes

* Translation – how to take known patterns and translate them to Rust?
* Start with the domain:
  * Drives all other code.
  * Requires few external crates.
  * Rust shines in parsing domain models and handling errors.
* Implement domain models: need key types to work with.
  * Consider lifetimes of string newtypes. Is it likely the reference will stick around as long as the type?
    * On the way in, yes. But not when retrieving them from database. Requires ownership.
  * Do we need mutability?
  * Consider basic trait implementations. It's helpful for us to treat a username as a string (e.g. for interfacing
    with a DB), but we don't want strings to be treated as usernames.
  * How to we ensure users cannot manipulate the internal representation of a type?
  * How do we ensure the type is always valid?
  * Error handling? How to we create a limited set of domain errors that we can guarantee are the only errors that
    will be returned?
  * new_unchecked: how to avoid abuse?
  * Deciding on from_str vs try_from. from_str allows you to skip lifetime parameters and accepts either &str or
    &String, which is convenient, but cannot be used to parse a struct that contains a reference. try_from allows this,
    but requires lifetime parameters and requires a separate implementation for &String.
* Errors
  * Style decision: full sentences except for fragments. Helps structuring more complex error messages.
  * How detailed can we be with error messages? E.g. collecting all invalid chars rather than terminating on the first
    one. Who is the audience? What do they need to know?
* Sudden leaps and starts. Sometimes, you step away for months, and when you come back, everything is easy. It has
  clicked.
* Testing. Unit tests in the same folder. Makes writing the tests feel a more central, fluid part of development.
  * Encourages more and easy tests.
* Copilot is superior for Rust than for Kotlin or Go. Surprising, since the language is more complex, but the greater
  structure may have led to fewer "correct" ways of doing things.
* Error message regarding FromResidual: might mean you're targeting a different error with the same name as the one
  you've implemented From for.