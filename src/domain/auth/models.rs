use argon2::{password_hash as argon2_password_hash, Argon2, PasswordHasher, PasswordVerifier};
use std::fmt;
use std::fmt::{Debug, Display};
use std::ops::Deref;
use std::str::FromStr;

/// Username is a string slice newtype representing a valid username.
#[derive(Debug, PartialEq)]
pub struct Username {
    raw: String,
}

const USERNAME_MIN_LENGTH: usize = 3;
const USERNAME_MAX_LENGTH: usize = 20;
const USERNAME_VALID_CHARS: &str = "a-zA-Z0-9_-";

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParseUsernameError {
    #[error("Username has less than {} characters.", USERNAME_MIN_LENGTH)]
    TooShort,
    #[error("Username has more than {} characters.", USERNAME_MAX_LENGTH)]
    TooLong,
    #[error(
        "Username contains invalid characters '{invalid_chars}'. Valid characters are '{}'.",
        USERNAME_VALID_CHARS
    )]
    InvalidChars {
        raw_username: String,
        invalid_chars: String,
    },
}

impl Username {
    /// Parse a string slice into a Username.
    pub fn parse(s: &str) -> Result<Self, ParseUsernameError> {
        if s.len() < USERNAME_MIN_LENGTH {
            return Err(ParseUsernameError::TooShort);
        }
        if s.len() > USERNAME_MAX_LENGTH {
            return Err(ParseUsernameError::TooLong);
        }

        let invalid_chars: String = s
            .chars()
            .filter(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
            .collect();

        if !invalid_chars.is_empty() {
            return Err(ParseUsernameError::InvalidChars {
                raw_username: s.to_string(),
                invalid_chars,
            });
        }

        Ok(Username { raw: s.to_owned() })
    }

    /// Create a Username without checking the validity of the input slice.
    pub fn new_unchecked(s: &str) -> Self {
        Username { raw: s.to_owned() }
    }
}

impl FromStr for Username {
    type Err = ParseUsernameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod username_tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let input = "abc";
        let expected = Username {
            raw: input.to_owned(),
        };
        let actual = Username::parse(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_too_short() {
        let input = "a".repeat(USERNAME_MIN_LENGTH - 1);
        let expected = ParseUsernameError::TooShort;
        let actual = Username::parse(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_too_long() {
        let input = "a".repeat(USERNAME_MAX_LENGTH + 1);
        let expected = ParseUsernameError::TooLong;
        let actual = Username::parse(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_invalid_chars() {
        let input = "a;bc$";
        let expected = ParseUsernameError::InvalidChars {
            raw_username: input.to_string(),
            invalid_chars: ";$".to_string(),
        };
        let actual = Username::parse(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_str_valid() {
        let input = "abc";
        let expected = Username {
            raw: input.to_owned(),
        };
        let actual = Username::from_str(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_str_too_short() {
        let input = "a".repeat(USERNAME_MIN_LENGTH - 1);
        let expected = ParseUsernameError::TooShort;
        let actual = Username::from_str(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_str_too_long() {
        let input = "a".repeat(USERNAME_MAX_LENGTH + 1);
        let expected = ParseUsernameError::TooLong;
        let actual = Username::from_str(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn new_unchecked() {
        let input = "abc";
        let expected = Username {
            raw: input.to_owned(),
        };
        let actual = Username::new_unchecked(input);
        assert_eq!(expected, actual);
    }
}

/// EmailAddress is a string slice newtype representing a valid email address.
#[derive(Debug, PartialEq)]
pub struct EmailAddress {
    raw: String,
}

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("Invalid email address '{}': {source}", email_address)]
pub struct ParseEmailAddressError {
    email_address: String,
    source: email_address::Error,
}

impl EmailAddress {
    pub fn parse(s: &str) -> Result<Self, ParseEmailAddressError> {
        if let Err(e) = email_address::EmailAddress::from_str(s) {
            return Err(ParseEmailAddressError {
                email_address: s.to_owned(),
                source: e,
            });
        }

        Ok(EmailAddress { raw: s.to_owned() })
    }

    pub fn new_unchecked(s: &str) -> Self {
        EmailAddress { raw: s.to_owned() }
    }
}

impl FromStr for EmailAddress {
    type Err = ParseEmailAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Deref for EmailAddress {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod email_address_tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let input = "test@test.com";
        let expected = EmailAddress {
            raw: input.to_owned(),
        };
        let actual = EmailAddress::parse(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_invalid() {
        let input = "test";
        let expected = ParseEmailAddressError {
            email_address: input.to_owned(),
            source: email_address::Error::MissingSeparator,
        };
        let actual = EmailAddress::parse(input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_str_valid() {
        let input = "test@test.com";
        let expected = EmailAddress {
            raw: input.to_owned(),
        };
        let actual = EmailAddress::from_str(input).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_str_invalid() {
        let input = "test";
        let expected = ParseEmailAddressError {
            email_address: input.to_owned(),
            source: email_address::Error::MissingSeparator,
        };
        let actual = EmailAddress::from_str(input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn new_unchecked() {
        let input = "test@test.com";
        let expected = EmailAddress {
            raw: input.to_owned(),
        };
        let actual = EmailAddress::new_unchecked(input);
        assert_eq!(expected, actual);
    }
}

const PASSWORD_MIN_LENGTH: usize = 8;
const PASSWORD_MAX_LENGTH: usize = 64;

/// Password is a string slice newtype representing a valid password.
/// An unhashed password should be strictly request-scoped. Hence, there
/// should be no need for Password to own its raw value.
#[derive(Clone, PartialEq)]
pub struct Password<'a> {
    raw: &'a str,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParsePasswordError {
    #[error("Password has fewer than {} characters.", PASSWORD_MIN_LENGTH)]
    TooShort,
    #[error("Password has more than {} characters.", PASSWORD_MAX_LENGTH)]
    TooLong,
}

impl<'a> Password<'a> {
    pub fn parse(raw: &'a str) -> Result<Self, ParsePasswordError> {
        if raw.len() < PASSWORD_MIN_LENGTH {
            return Err(ParsePasswordError::TooShort);
        }
        if raw.len() > PASSWORD_MAX_LENGTH {
            return Err(ParsePasswordError::TooLong);
        }

        Ok(Password { raw })
    }
}

impl<'a> TryFrom<&'a str> for Password<'a> {
    type Error = ParsePasswordError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl Deref for Password<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.raw
    }
}

impl AsRef<str> for Password<'_> {
    fn as_ref(&self) -> &str {
        self.raw
    }
}

impl Debug for Password<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password")
            .field("raw", &"REDACTED")
            .finish()
    }
}

impl Display for Password<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let expected = Password { raw: input };
        let actual = Password::parse(input).unwrap();
        assert_eq!(
            expected, actual,
            "Expected Password with raw value '{}', got '{}'.",
            input, actual.raw,
        );
    }

    #[test]
    fn parse_too_short() {
        let input = "a".repeat(PASSWORD_MIN_LENGTH - 1);
        let expected = ParsePasswordError::TooShort;
        let actual = Password::parse(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_too_long() {
        let input = "a".repeat(PASSWORD_MAX_LENGTH + 1);
        let expected = ParsePasswordError::TooLong;
        let actual = Password::parse(&input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn try_from_valid() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH)[..];
        let expected = Password::parse(input).unwrap();
        let actual = Password::try_from(input).unwrap();
        assert_eq!(
            expected, actual,
            "Expected Password with raw value '{}', got '{}'.",
            input, actual.raw,
        );
    }

    #[test]
    fn try_from_too_short() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH - 1)[..];
        let expected = ParsePasswordError::TooShort;
        let actual = Password::try_from(input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn try_from_too_long() {
        let input = &"a".repeat(PASSWORD_MAX_LENGTH + 1)[..];
        let expected = ParsePasswordError::TooLong;
        let actual = Password::try_from(input).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn debug() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let password = Password::parse(input).unwrap();
        let expected = "Password { raw: \"REDACTED\" }";
        let actual = format!("{:?}", password);
        assert_eq!(expected, actual);
    }

    #[test]
    fn display() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let password = Password::parse(input).unwrap();
        let expected = "REDACTED";
        let actual = format!("{}", password);
        assert_eq!(expected, actual);
    }
}

/// PasswordHash is a string slice newtype representing a hashed password.
pub struct PasswordHash {
    hash: String,
}

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("Failed to hash password: {source}")]
pub struct HashPasswordError {
    #[from]
    source: argon2_password_hash::Error,
}

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("Password and hash did not match.")]
pub struct ComparePasswordError {
    #[from]
    source: argon2_password_hash::Error,
}

impl PasswordHash {
    /// Hash a raw password, consuming it in the process.
    pub fn hash(password: Password) -> Result<Self, HashPasswordError> {
        let salt =
            argon2_password_hash::SaltString::generate(argon2_password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.into())
    }

    /// Compare a raw password to this hash.
    fn compare(&self, password: Password) -> Result<(), ComparePasswordError> {
        Argon2::default().verify_password(password.as_bytes(), &self.into())?;
        Ok(())
    }
}

impl<'a> From<&'a PasswordHash> for argon2::PasswordHash<'a> {
    fn from(hash: &'a PasswordHash) -> Self {
        // All domain PasswordHash hashes are derived from Argon2, so this unwrap is safe.
        argon2::PasswordHash::new(&hash.hash).unwrap()
    }
}

impl<'a> From<argon2::PasswordHash<'a>> for PasswordHash {
    fn from(argon2_hash: argon2_password_hash::PasswordHash) -> Self {
        PasswordHash {
            hash: argon2_hash.to_string(),
        }
    }
}

impl Deref for PasswordHash {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.hash
    }
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        &self.hash
    }
}

#[cfg(test)]
mod password_hash_tests {
    use super::*;

    #[test]
    fn parse_and_compare_valid() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let password = Password::parse(input).unwrap();
        let hash = PasswordHash::hash(password.clone()).unwrap();
        hash.compare(password).unwrap();
    }

    #[test]
    fn parse_and_compare_mismatch() {
        let input_a = &"a".repeat(PASSWORD_MIN_LENGTH);
        let input_b = &"b".repeat(PASSWORD_MIN_LENGTH);
        let password = Password::parse(input_a).unwrap();
        let hash = PasswordHash::hash(password.clone()).unwrap();
        let mismatch = Password::parse(input_b).unwrap();
        let expected = ComparePasswordError {
            source: argon2_password_hash::Error::Password,
        };
        let actual = hash.compare(mismatch).unwrap_err();
        assert_eq!(expected, actual);
    }

    #[test]
    fn argon2_hash_from_password_hash() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let password = Password::parse(input).unwrap();
        let hash = PasswordHash::hash(password.clone()).unwrap();
        let expected = argon2_password_hash::PasswordHash::new(&hash.hash).unwrap();
        let actual = argon2_password_hash::PasswordHash::from(&hash);
        assert_eq!(expected, actual);
    }

    #[test]
    fn password_hash_from_argon2_hash() {
        let input = &"a".repeat(PASSWORD_MIN_LENGTH);
        let salt =
            argon2_password_hash::SaltString::generate(argon2_password_hash::rand_core::OsRng);
        let argon2_hash = Argon2::default()
            .hash_password(input.as_bytes(), &salt)
            .unwrap();
        let expected = PasswordHash {
            hash: argon2_hash.to_string(),
        };
        let actual = PasswordHash::from(argon2_hash);
        assert_eq!(expected.hash, actual.hash);
    }
}

/// RegistrationRequest contains the valid data required to register a new user.
pub struct RegistrationRequest<'a> {
    pub username: &'a Username,
    pub email_address: &'a EmailAddress,
    pub password_hash: &'a PasswordHash,
}
