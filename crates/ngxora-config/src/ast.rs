#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ast {
    pub items: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Directive(Directive),
    Block(Block),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub name: String,
    pub args: Vec<String>,
    pub children: Vec<Node>,
}
