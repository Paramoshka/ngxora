#[derive(Debug, PartialEq, Eq)]
pub enum BlockName {
    Http,
    Server,
    Location,
    Other(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectiveName {
    Listen,
    ServerName,
    Include,
    Other(String),
}
