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
            })
        };

        let nodes = resolve_nodes(&ast.items, &loader)?;
        Ok(Ast { items: nodes })
    }
}

// It does not perform a payload yet, it may be necessary to expand the functionality.
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

fn resolve_nodes<F>(nodes: &[Node], loader: &F) -> Result<Vec<Node>, IncludeError>
where
    F: Fn(&str) -> Result<String, IncludeError>,
{
    let mut out: Vec<Node> = Vec::new();

    for node in nodes {
        match node {
            Node::Directive(directive) if directive.name == INCLUDE_DIRECTIVE => {
                for path in &directive.args {
                    let text = loader(path)?;
                    let ast = Ast::parse_config(&text)
                        .map_err(|e| IncludeError { message: e.message })?;

                    out.extend(resolve_nodes(&ast.items, loader)?);
                }
            }

            Node::Block(block) => {
                let children = resolve_nodes(&block.children, loader)?;
                out.push(Node::block(
                    block.name.clone(),
                    block.args.clone(),
                    children,
                ));
            }

            other => out.push(other.clone()),
        }
    }

    Ok(out)
}
