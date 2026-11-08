//! Sigma rule parser for ZAAFElegia.

/// Version of the Sigma specification this crate implements.
pub const SPEC_VERSION: &str = "2.1.0";

#[cfg(test)]
mod tests {
    #[test]
    fn spec_version_is_2_1() {
        assert_eq!(super::SPEC_VERSION, "2.1.0");
    }
}
