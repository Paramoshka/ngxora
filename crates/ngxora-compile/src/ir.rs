#[derive(Debug, Eq, PartialEq)]
pub struct Ir {}

#[derive(Debug, Eq, PartialEq)]
pub struct Http {
    pub servers: Vec<Server>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Server {}

#[derive(Debug, Eq, PartialEq)]
pub struct Location {}
