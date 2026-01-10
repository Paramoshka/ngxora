use ngxora_config::{Ast, Node};

use crate::{consts, ir::{Http, Ir}};

impl Ir {
    pub fn from_ast(ast: &Ast) -> Self {
        let mut ir = Ir::default();
        let mut http: Option<Http> = None;
        for node in &ast.items {
            match node {
                Node::Directive(_directive) => {}
                Node::Block(block) => match block.name.as_str() {
                    consts::HTTP => {
                        if http.is_some() {
                            continue;
                        }
                        http = Some(Http { servers: Vec::new() });
                        // TODO: lower `block.children` into `http.servers`
                    }
                    _ => {}
                },
            }
        }

        ir.http = http;
        ir
    }
}
