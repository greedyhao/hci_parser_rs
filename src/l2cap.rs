use crate::InnerStack;
use crate::ParseLayer;

struct L2cap {
    pdu_length: u16,
    channel_id: u16,
}

impl L2cap {
    fn new(data: &[u8]) -> Self {
        let pdu_length = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let channel_id = u16::from_le_bytes(data[2..4].try_into().unwrap());
        L2cap {
            pdu_length,
            channel_id,
        }
    }
}

impl ParseLayer for L2cap {
    fn to_json(&self) -> (String, String) {
        let pdu_length_s = "PDU Length";
        let channel_id_s = "Channel ID";

        let mut major = format!(
            r#"{{"{}":"{:#x}", "{}":"{:#x}""#,
            pdu_length_s, self.pdu_length, channel_id_s, self.channel_id
        );

        let mut minor = format!(
            r#"{{"{}":"(0,2)", "{}":"(2,2)""#,
            self.pdu_length, self.channel_id
        );

        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

pub fn parse(data: &[u8], _args: &mut InnerStack) -> Vec<Box<dyn ParseLayer>> {
    // println!("{:?}", data);
    vec![Box::new(L2cap::new(data))]
}
