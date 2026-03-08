use crate::{Ast, Node};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const INCLUDE_DIRECTIVE: &str = "include";
const MAX_INCLUDE_DEPTH: usize = 16;

#[derive(Debug, Default)]
pub struct IncludeResolver {
    pub includes_files: Vec<IncludeFile>,
    root_dir: PathBuf,
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
    pub fn new(ast: &Ast, root_dir: impl Into<PathBuf>) -> Self {
        let mut includes_files: Vec<IncludeFile> = Vec::new();
        collect_includes(&ast.items, &mut includes_files);

        IncludeResolver {
            includes_files: includes_files,
            root_dir: root_dir.into(),
        }
    }

    pub fn resolve(&self, ast: &Ast) -> Result<Ast, IncludeError> {
        let root_dir = std::fs::canonicalize(&self.root_dir).map_err(|e| IncludeError {
            message: format!(
                "failed to canonicalize include root {}: {e}",
                self.root_dir.display()
            ),
        })?;

        let mut resolving = HashSet::new();
        let nodes = resolve_nodes(&ast.items, &root_dir, &root_dir, &mut resolving, 0)?;
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

fn resolve_nodes(
    nodes: &[Node],
    root_dir: &Path,
    current_dir: &Path,
    resolving: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<Vec<Node>, IncludeError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(IncludeError {
            message: format!("include: maximum nested depth {MAX_INCLUDE_DEPTH} exceeded"),
        });
    }

    let mut out: Vec<Node> = Vec::new();

    for node in nodes {
        match node {
            Node::Directive(directive) if directive.name == INCLUDE_DIRECTIVE => {
                for path in &directive.args {
                    let include_path = resolve_include_path(root_dir, current_dir, path)?;
                    if !resolving.insert(include_path.clone()) {
                        return Err(IncludeError {
                            message: format!(
                                "include cycle detected while resolving {}",
                                include_path.display()
                            ),
                        });
                    }

                    let text =
                        std::fs::read_to_string(&include_path).map_err(|e| IncludeError {
                            message: format!(
                                "failed to read include {}: {e}",
                                include_path.display()
                            ),
                        })?;
                    let ast = Ast::parse_config(&text)
                        .map_err(|e| IncludeError { message: e.message })?;
                    let next_dir = include_path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| root_dir.to_path_buf());

                    out.extend(resolve_nodes(
                        &ast.items,
                        root_dir,
                        &next_dir,
                        resolving,
                        depth + 1,
                    )?);
                    resolving.remove(&include_path);
                }
            }

            Node::Block(block) => {
                let children =
                    resolve_nodes(&block.children, root_dir, current_dir, resolving, depth)?;
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

fn resolve_include_path(
    root_dir: &Path,
    current_dir: &Path,
    raw_path: &str,
) -> Result<PathBuf, IncludeError> {
    let path = Path::new(raw_path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };

    let canonical = std::fs::canonicalize(&path).map_err(|e| IncludeError {
        message: format!("failed to resolve include {}: {e}", path.display()),
    })?;

    if !canonical.starts_with(root_dir) {
        return Err(IncludeError {
            message: format!(
                "include path {} escapes root config directory {}",
                canonical.display(),
                root_dir.display()
            ),
        });
    }

    Ok(canonical)
}
