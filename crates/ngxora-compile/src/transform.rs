use ngxora_config::{Ast, Block, Directive, Node};

use crate::{
    consts,
    ir::{Http, Ir, Location, Server},
};

pub struct LowerErr {
    pub message: String,
}

impl Ir {
    pub fn from_ast(ast: &Ast) -> Self {
        let mut ir = Ir::default();
        let mut http: Option<Http> = None;
        for node in &ast.items {
            match node {
                Node::Directive(_directive) => {}
                Node::Block(block) => match block.name.as_str() {
                    consts::HTTP => match lower_http(block) {
                        Ok(h) => http = Some(h),
                        Err(_) => todo!(),
                    },
                    _ => {}
                },
            }
        }

        ir.http = http;
        ir
    }
}

fn lower_http(block: &Block) -> Result<Http, LowerErr> {
    let mut http: Http = Http {
        servers: Vec::new(),
    };

    for children_block in &block.children {
        match children_block {
            Node::Directive(directive) => apply_http_directive(&mut http, directive)?,
            Node::Block(block) => todo!(),
        }
    }

    Ok(http)
}

fn apply_http_directive(http: &mut Http, d: &Directive) -> Result<(), LowerErr> {
    match d.name.as_str() {
        consts::KEEPALIVE_TIMEOUT => {
            todo!()
        }
        consts::TCP_NODELAY => {
            todo!()
        }
        _ => {
            todo!()
        }
    }

    Ok(())
}

fn lower_server(block: &Block) -> Result<Server, LowerErr> {
    todo!()
}

fn lower_location(block: &Block) -> Result<Location, LowerErr> {
    todo!()
}

fn block_named<'a>(node: &'a Node, name: &'a str) -> Option<&'a Block> {
    match node {
        Node::Block(block) if name == block.name => Some(block),
        _ => None,
    }
}
