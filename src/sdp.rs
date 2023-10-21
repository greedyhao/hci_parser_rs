use crate::HostStack;
use crate::ParseNodeOpt;

use crate::ParseBytesNode;

#[derive(Default, Debug, Clone)]
pub struct SDPArg {}

#[derive(Debug, Default, PartialEq)]
pub struct SDP {
    pdu_id: u8,
    trans_id: u16,
    param_len: u16,
}

impl ParseNodeOpt for SDP {
    fn new(data: &[u8], _args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        Some(SDP {
            pdu_id: data[0],
            trans_id: u16::from_le_bytes([data[1], data[2]]),
            param_len: u16::from_le_bytes([data[3], data[4]]),
        })
    }
    fn as_json(&self, start_byte: u8) -> String {
        let pdu_id_s = ParseBytesNode::new(start_byte, 1).format("PDU ID", self.pdu_id, "", "");
        let trans_id_s =
            ParseBytesNode::new(start_byte + 1, 2).format("Transaction ID", self.trans_id, "", "");
        let param_len_s = ParseBytesNode::new(start_byte + 3, 2).format(
            "Parameter Length",
            self.param_len,
            "",
            "",
        );
        format!(
            r#""SDP": {{{}, {}, {}}}"#,
            pdu_id_s, trans_id_s, param_len_s
        )
    }
}
