use arc_swap::ArcSwap;

pub struct Ast {
    pub directives: ArcSwap<Vec<Directive>>,
}

pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
}

pub struct Block {
    pub name: String,
    pub args: Vec<String>,
}
