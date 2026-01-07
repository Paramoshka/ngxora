use crate::{Ast, Block, Node};

const INCLUDE_DIRECTIVE: &str = "include";

#[derive(Debug, Default)]
pub struct IncludeResolver {
    pub includes_files: Vec<IncludeFile>,
}

#[derive(Debug)]
pub struct IncludeFile {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeError {
    pub message: String,
}

impl IncludeResolver {
    pub fn new(ast: &Ast) -> Self {
        let mut includes_files: Vec<IncludeFile> = Vec::new();
        collect_includes(&ast.items, &mut includes_files);

        IncludeResolver {
            includes_files: includes_files,
        }
    }

    pub fn resolve(&self) -> Result<Ast, IncludeError> {
        // TODO replace includes on Nodes
        todo!()
    }
}

fn collect_includes(nodes: &[Node], out: &mut Vec<IncludeFile>) {
    for node in nodes {
        match node {
            Node::Directive(directive) if directive.name == INCLUDE_DIRECTIVE => {
                for inc_file_path in &directive.args {
                    out.push(IncludeFile {
                        path: inc_file_path.clone(),
                        text: String::new(),
                    });
                }
            }
            Node::Block(block) => collect_includes(&block.children, out),
            _ => {}
        }
    }
}
