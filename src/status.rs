use strum_macros::{Display, EnumString};

#[derive(Debug, PartialEq, Clone, EnumString, Display)]
pub enum ServerStatus {
    #[strum(to_string = "Unknown")]
    Unknown,
    #[strum(to_string = "Free")]
    Free,
    #[strum(to_string = "Working")]
    Working,
    #[strum(to_string = "Locked")]
    Locked,
}

impl Default for ServerStatus {
    fn default() -> Self {
        ServerStatus::Free
    }
}