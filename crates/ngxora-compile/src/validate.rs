use crate::ir::Ir;

pub struct ValidateErr {
    pub message: String,
}

impl Ir {
    pub fn validate(&self) -> Result<(), ValidateErr> {
        todo!()
    }
}
