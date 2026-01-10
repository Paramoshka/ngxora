use ngxora_config::Ast;

use crate::ir::Ir;

impl Ir {
    pub fn new(&self, ast: &Ast) -> Self {
        let ir: Ir = Ir::default();
        for node in &ast.items {
            match node {
                ngxora_config::Node::Directive(directive) => todo!(),
                ngxora_config::Node::Block(block) => todo!(),
            }
        }

        ir
    }
}
