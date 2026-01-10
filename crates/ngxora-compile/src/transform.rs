use ngxora_config::{Ast, Block, Node};

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
                    consts::HTTP => {}
                    _ => {}
                },
            }
        }

        ir.http = http;
        ir
    }
}

fn lower_http(block: &Block) -> Result<Http, LowerErr> {
    todo!()
}

fn lower_server(block: &Block) -> Result<Server, LowerErr> {
    todo!()
}

fn lower_location(block: &Block) -> Result<Location, LowerErr> {
    todo!()
}

fn block_named(node: &Node, name: &str) -> Option<Block> {
    match node {
        Node::Block(block) => todo!(),
        _ => None,
    }
}
