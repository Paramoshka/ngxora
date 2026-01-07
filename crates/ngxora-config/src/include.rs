use crate::Ast;

#[derive(Debug, Default)]
pub struct IncludeResolver<'a> {
    pub includes_files: Vec<IncludeFile<'a>>,
}

#[derive(Debug)]
pub struct IncludeFile<'a> {
    pub path: String,
    pub text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeError {
    pub message: String,
}

impl IncludeResolver {
    pub fn new(&self, ast: Ast) -> IncludeResolver {
        IncludeResolver {
            includes_files: Vec::new(),
        }
    }

    pub fn resolve(&self) -> Result<Ast, IncludeError> {
        // TODO replace includes on Nodes
    }
}
