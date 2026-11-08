//! Diagnostics reported while parsing and compiling rules.

use std::fmt;
use std::path::PathBuf;

/// How serious a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// Where in a file a diagnostic points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    Unknown,
    /// 1-based line and column, plus the dotted YAML path of the node
    /// (e.g. `detection.selection.Image|endswith`). `path` is empty when no
    /// path applies, e.g. for YAML syntax errors or a whole document.
    At {
        line: usize,
        col: usize,
        path: String,
    },
}

impl Location {
    pub fn at(line: usize, col: usize, path: impl Into<String>) -> Self {
        Self::At {
            line,
            col,
            path: path.into(),
        }
    }
}

/// A problem found in a rule, pipeline or input file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub file: Option<PathBuf>,
    pub location: Location,
    pub message: String,
}

impl Diagnostic {
    pub fn error(location: Location, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            file: None,
            location,
            message: message.into(),
        }
    }

    pub fn warning(location: Location, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            file: None,
            location,
            message: message.into(),
        }
    }

    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let file = self
            .file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<input>".to_string());
        match &self.location {
            Location::Unknown => write!(f, "{sev}: {file}: {}", self.message),
            Location::At { line, col, path } if path.is_empty() => {
                write!(f, "{sev}: {file}:{line}:{col}: {}", self.message)
            }
            Location::At { line, col, path } => {
                write!(f, "{sev}: {file}:{line}:{col}: {path}: {}", self.message)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_line_and_column() {
        let d = Diagnostic::error(Location::at(3, 7, ""), "bad").with_file("r.yml");
        assert_eq!(d.to_string(), "error: r.yml:3:7: bad");
    }

    #[test]
    fn displays_position_and_yaml_path() {
        let d = Diagnostic::warning(Location::at(12, 9, "detection.sel.Image"), "unmapped");
        assert_eq!(
            d.to_string(),
            "warning: <input>:12:9: detection.sel.Image: unmapped"
        );
        assert_eq!(
            d.location,
            Location::At {
                line: 12,
                col: 9,
                path: "detection.sel.Image".into()
            }
        );
    }

    #[test]
    fn displays_unknown_location() {
        let d = Diagnostic::error(Location::Unknown, "boom").with_file("x.yml");
        assert_eq!(d.to_string(), "error: x.yml: boom");
        assert!(d.is_error());
    }
}
