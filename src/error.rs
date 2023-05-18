use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct OvenrackError {
    details: String,
}

impl OvenrackError {
    pub fn new<S: Into<String>>(msg: S) -> OvenrackError {
        OvenrackError {
            details: msg.into(),
        }
    }
}

impl fmt::Display for OvenrackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for OvenrackError {
    fn description(&self) -> &str {
        &self.details
    }
}
