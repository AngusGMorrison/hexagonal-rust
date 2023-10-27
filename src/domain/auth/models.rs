use std::ops::Deref;
use std::str::FromStr;

/// Username is a string slice newtype representing a valid username.
#[derive(Debug, PartialEq)]
pub struct Username<'a> {
    raw: &'a str,
}

const USERNAME_MIN_LENGTH: u8 = 3;
const USERNAME_MAX_LENGTH: u8 = 20;
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
    InvalidChars{
        raw_username: String,
        invalid_chars: String,
    },
}

impl <'a> Username<'a> {
    /// Parse a string slice into a Username.
    fn parse(raw: &'a str) -> Result<Self, ParseUsernameError> {
        if raw.len() < 3 {
            return Err(ParseUsernameError::TooShort);
        }
        if raw.len() > 20 {
            return Err(ParseUsernameError::TooLong);
        }

        let invalid_chars: String =  raw
            .chars()
            .filter(| c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
            .collect();

        if !invalid_chars.is_empty() {
            return Err(ParseUsernameError::InvalidChars{
                raw_username: raw.to_string(),
                invalid_chars,
            });
        }

        Ok(Username{ raw })
    }

    /// Create a Username without checking the validity of the input slice.
    fn new_unchecked(raw: &'a str) -> Self {
        Username{ raw }
    }
}

impl <'a> TryFrom<&'a str> for Username<'a> {
    type Error = ParseUsernameError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl Deref for Username<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.raw
    }
}

impl AsRef<str> for Username<'_> {
    fn as_ref(&self) -> &str {
        self.raw
    }
}

#[cfg(test)]
mod username_tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let raw = "abc";
        let username = Username::parse(raw).unwrap();
        assert_eq!(Username{ raw: raw }, username);
    }

    #[test]
    fn parse_too_short() {
        let raw = "a".repeat(USERNAME_MIN_LENGTH as usize - 1);
        let err = Username::parse(&raw).unwrap_err();
        assert_eq!(ParseUsernameError::TooShort, err);
    }

    #[test]
    fn parse_too_long() {
        let raw = "a".repeat(USERNAME_MAX_LENGTH as usize + 1);
        let err = Username::parse(&raw).unwrap_err();
        assert_eq!(ParseUsernameError::TooLong, err);
    }

    #[test]
    fn parse_invalid_chars() {
        let raw = "a;bc$";
        let err = Username::parse(&raw).unwrap_err();
        assert_eq!(ParseUsernameError::InvalidChars{
            raw_username: raw.to_string(),
            invalid_chars: ";$".to_string(),
        }, err);
    }

    #[test]
    fn new_unchecked() {
        let raw = "abc";
        let username = Username::new_unchecked(raw);
        assert_eq!(Username{ raw }, username);
    }
}

/// EmailAddress is a string slice newtype representing a valid email address.
#[derive(Debug, PartialEq)]
pub struct EmailAddress<'a> {
    raw: &'a str,
}

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("Invalid email address: {source}")]
pub struct ParseEmailAddressError {
    source: email_address::Error,
}

impl <'a> EmailAddress<'a> {
    fn parse(raw: &'a str) -> Result<Self, ParseEmailAddressError> {
        if let Err(e) = email_address::EmailAddress::from_str(raw) {
            return Err(ParseEmailAddressError{ source: e });
        }

        Ok(EmailAddress{ raw })
    }

    fn new_unchecked(raw: &'a str) -> Self {
        EmailAddress{ raw }
    }
}

impl <'a> TryFrom<&'a str> for EmailAddress<'a> {
    type Error = ParseEmailAddressError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl Deref for EmailAddress<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.raw
    }
}

impl AsRef<str> for EmailAddress<'_> {
    fn as_ref(&self) -> &str {
        self.raw
    }
}

#[cfg(test)]
mod email_address_tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let raw = "test@test.com";
        let email_address = EmailAddress::parse(raw).unwrap();
        assert_eq!(EmailAddress { raw }, email_address);
    }

    #[test]
    fn parse_invalid() {
        let raw = "test";
        let err = EmailAddress::parse(raw).unwrap_err();
        assert_eq!(ParseEmailAddressError{ source: email_address::Error::MissingSeparator }, err);
    }

    #[test]
    fn new_unchecked() {
        let raw = "test@test.com";
        let email_address = EmailAddress::new_unchecked(raw);
        assert_eq!(EmailAddress { raw }, email_address);
    }
}

pub struct PasswordCandidate<'a>(&'a str);

impl <'a> From<&'a str> for PasswordCandidate<'a> {
    fn from(s: &'a str) -> Self {
        PasswordCandidate(s)
    }
}

impl Deref for PasswordCandidate<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl AsRef<str> for PasswordCandidate<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub struct RegistrationRequest<'a> {
    pub username: &'a Username<'a>,
    pub email_address: &'a EmailAddress<'a>,
    pub password_candidate: &'a PasswordCandidate<'a>,
}

