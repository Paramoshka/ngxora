use crate::{Ast, Node};

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

    pub fn resolve(&self, ast: &Ast) -> Result<Ast, IncludeError> {
        let loader = |path: &str| {
            std::fs::read_to_string(path).map_err(|e| IncludeError {
                message: e.to_string(),
            });
        };

        let nodes = resolve_nodes(&ast.items, &loader)?;
        Ok(Ast { items: nodes })
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

fn resolve_nodes(nodes: &[Node], load: &impl Fn(&str)) -> Result<Vec<Node>, IncludeError> {
    let mut out: Vec<Node> = Vec::new();

    for node in nodes {
        match node {
            Node::Directive(directive) => todo!(),

            Node::Block(block) => todo!(),

            other => out.push(other.clone()),
        }
    }

    Ok(out)
}
