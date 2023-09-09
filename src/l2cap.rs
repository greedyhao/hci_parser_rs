use crate::InnerStack;
use crate::ParseLayer;

// 0x40-0xffff is dynamically allocated
enum CID {
    NullIdentifier = 0x00,
    L2capSignalingChannel,
    ConnetionlessChannel,
    PreviouslyUsed1,
    BrEdrSecurityManager = 0x07,
    PreviouslyUsed2 = 0x3f,
    DynamicallyAllocated = 0x40,
}

impl CID {
    fn from_u16(cid: u16) -> Self {
        use CID::*;
        match cid {
            0x00 => NullIdentifier,
            0x01 => L2capSignalingChannel,
            0x02 => ConnetionlessChannel,
            0x03 => PreviouslyUsed1,
            0x07 => BrEdrSecurityManager,
            0x3f => PreviouslyUsed2,
            0x40..=0xffff => DynamicallyAllocated,
            _ => NullIdentifier,
        }
    }
}

impl std::fmt::Display for CID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CID::*;
        let str = match &self {
            NullIdentifier => "Null identifier or Undefined",
            L2capSignalingChannel => "L2CAP Signaling channel",
            ConnetionlessChannel => "Connectionless channel",
            PreviouslyUsed1 | PreviouslyUsed2 => "Previously used",
            BrEdrSecurityManager => "BR/EDR Security Manager",
            DynamicallyAllocated => "Dynamically allocated",
        };
        write!(f, "{}", str)
    }
}

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
            r#"{{"{}":"{:#x}", "{}":"{:#x}({})""#,
            pdu_length_s,
            self.pdu_length,
            channel_id_s,
            self.channel_id,
            CID::from_u16(self.channel_id)
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
    let l2cap = L2cap::new(data);
    vec![Box::new(l2cap)]
}
