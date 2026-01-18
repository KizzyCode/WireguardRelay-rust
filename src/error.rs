//! Implements the crate's error type

use crate::LOGLEVEL;
use crate::config::Config;
use std::backtrace::{Backtrace, BacktraceStatus};
use std::fmt::{self, Display, Formatter};
use std::io::Write;
use std::{error, io};

/// Creates a new error
#[macro_export]
macro_rules! error {
    (with: $error:expr, $($arg:tt)*) => {{
        let error = format!($($arg)*);
        let source = Box::new($error);
        $crate::error::Error::new(error, Some(source))
    }};
    ($($arg:tt)*) => {{
        let error = format!($($arg)*);
        $crate::error::Error::new(error, None)
    }};
}

/// Logs an error or a result if it contains an error
#[macro_export]
macro_rules! log {
    (fatal: $result:expr) => {
        $crate::error::Loggable::log($result, 0)
    };
    (warn: $result:expr) => {
        $crate::error::Loggable::log($result, 1)
    };
    (info: $result:expr) => {
        $crate::error::Loggable::log($result, 2)
    };
    (debug: $result:expr) => {
        $crate::error::Loggable::log($result, 3)
    };
}

/// The crates error type
#[derive(Debug)]
pub struct Error {
    /// The error description
    pub error: String,
    /// The underlying error
    pub source: Option<Box<dyn error::Error + Send>>,
    /// The backtrace
    pub backtrace: Backtrace,
}
impl Error {
    /// Creates a new error
    #[doc(hidden)]
    pub fn new(error: String, source: Option<Box<dyn error::Error + Send>>) -> Self {
        let backtrace = Backtrace::capture();
        Self { error, source, backtrace }
    }

    /// Whether the error has captured a backtrace or not
    pub fn has_backtrace(&self) -> bool {
        self.backtrace.status() == BacktraceStatus::Captured
    }
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the error
        write!(f, "{}", self.error)?;

        // Print the source
        if let Some(source) = &self.source {
            writeln!(f)?;
            write!(f, " caused by: {source}")?;
        }
        Ok(())
    }
}
impl<T> From<T> for Error
where
    T: error::Error + Send + 'static,
{
    fn from(source: T) -> Self {
        let error = source.to_string();
        let source = Box::new(source);
        Self::new(error, Some(source))
    }
}

/// A helper trait for stuff that can be logged
pub trait Loggable
where
    Self: Sized,
{
    /// Converts a severity level to a logging prefix
    fn log(self, severity: u8) -> Self {
        // Check if we should even log
        let false = self.skip() else {
            // This instance should not be logged
            return self;
        };
        let true = severity <= LOGLEVEL.get() else {
            // Log level is not verbose enough
            return self;
        };

        // Select the correct prefix
        let prefix = match severity {
            0 => "[FAIL] ",
            1 => "[WARN] ",
            2 => "[INFO] ",
            _ => "[DEBG] ",
        };

        // Write self to `stderr`
        let mut stderr = io::stderr();
        let _ = write!(&mut stderr, "{prefix}");
        let _ = self.write(&mut stderr);
        let _ = writeln!(&mut stderr);
        let _ = stderr.flush();

        // Allow chaining
        self
    }

    /// If logging `self` should be skipped or not
    #[must_use]
    fn skip(&self) -> bool {
        false
    }

    /// Formats `self` and writes it to the given `sink`
    fn write(&self, sink: &mut dyn Write) -> Result<(), io::Error>;
}
impl Loggable for &Error {
    fn write(&self, sink: &mut dyn Write) -> Result<(), io::Error> {
        write!(sink, "{self}")?;
        if self.has_backtrace() {
            // Print the backtrace if any
            writeln!(sink)?;
            write!(sink, "{}", self.backtrace)?;
        };
        Ok(())
    }
}
impl Loggable for Error {
    fn write(&self, sink: &mut dyn Write) -> Result<(), io::Error> {
        let error: &Error = self;
        Loggable::write(&error, sink)
    }
}
impl<T> Loggable for Result<T, Error> {
    fn skip(&self) -> bool {
        self.is_ok()
    }

    fn write(&self, sink: &mut dyn Write) -> Result<(), io::Error> {
        match self.as_ref() {
            Err(e) => e.write(sink),
            Ok(_) => panic!("trying to log `Result::Ok` variant"),
        }
    }
}
impl Loggable for &Config {
    fn write(&self, sink: &mut dyn Write) -> Result<(), io::Error> {
        write!(sink, "{self}")
    }
}
