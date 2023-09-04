use crate::InnerStack;
use crate::ParseLayer;

struct L2cap {}

impl ParseLayer for L2cap {
    fn to_json(&self) -> (String, String) {
        (String::new(), String::new())
    }
}

pub fn parse(_data: &[u8], _args: &mut InnerStack) -> Vec<Box<dyn ParseLayer>> {
    vec![Box::new(L2cap {})]
}
