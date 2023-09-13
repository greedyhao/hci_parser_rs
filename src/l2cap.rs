use crate::InnerStack;
use crate::ParseLayer;
use crate::ParseNode;
use crate::ParseStatus;

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

struct L2capHeader {
    pdu_length: u16,
    channel_id: u16,
}

impl L2capHeader {
    fn new(data: &[u8]) -> Self {
        let pdu_length = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let channel_id = u16::from_le_bytes(data[2..4].try_into().unwrap());
        L2capHeader {
            pdu_length,
            channel_id,
        }
    }
}

impl ParseLayer for L2capHeader {
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

        (major, minor)
    }
}

struct L2capDummy {}

impl ParseLayer for L2capDummy {
    fn to_json(&self) -> (String, String) {
        (String::new(), String::new())
    }
}

enum SignalCommandCode {
    SignalUndefinedCode = 0x00,
    CommandRejectRspCode,
    ConnectionReqCode,
    ConnectionRspCode,
    ConfigurationReqCode,
    ConfigurationRspCode,
    DisconnectionReqCode,
    DisconnectionRspCode,
    EchoReqCode,
    EchoRspCode,
    InformationReqCode,
    InformationRspCode,
}

impl SignalCommandCode {
    fn from_u8(code: u8) -> Self {
        use SignalCommandCode::*;
        match code {
            0x01 => CommandRejectRspCode,
            0x02 => ConnectionReqCode,
            0x03 => ConnectionRspCode,
            0x04 => ConfigurationReqCode,
            0x05 => ConfigurationRspCode,
            0x06 => DisconnectionReqCode,
            0x07 => DisconnectionRspCode,
            0x08 => EchoReqCode,
            0x09 => EchoRspCode,
            0x0A => InformationReqCode,
            0x0B => InformationRspCode,
            _ => SignalUndefinedCode,
        }
    }
}

struct SignalCommand<T> {
    code: u8,
    identifier: u8,
    data_length: u16,
    data: T,
}

impl<T: ParseNode> ParseLayer for SignalCommand<T> {
    fn to_json(&self) -> (String, String) {
        let code_s = "Code";
        let identifier_s = "Identifier";
        let data_length_s = "Data Length";

        let mut major = format!(
            r#", "{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}""#,
            code_s, self.code, identifier_s, self.identifier, data_length_s, self.data_length,
        );

        let mut minor = format!(
            r#", "{}":"(0,1)", "{}":"(1,1)", "{}":"(2,2)""#,
            code_s, identifier_s, data_length_s
        );

        let info = self.data.get_info();
        let mut cnt = 4;
        for sub in info.1 {
            major.push_str(format!(r#", "{}":"{}""#, sub.0, sub.1).as_str());
            minor.push_str(format!(r#", "{}":"({},{})""#, sub.0, cnt, sub.2).as_str());
            if sub.3 != ParseStatus::Ok {
                minor.push_str(format!(r#",{}"#, sub.3 as u8).as_str());
            }
            cnt += sub.2;
        }

        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

impl<T: ParseNode> ParseNode for SignalCommand<T> {
    fn get_info(&self) -> (String, Vec<(String, String, u8, crate::ParseStatus)>) {
        std::unimplemented!()
    }
    fn new(data: &[u8]) -> Self {
        SignalCommand {
            code: data[0],
            identifier: data[1],
            data_length: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            data: T::new(&data[4..]),
        }
    }
}

#[derive(Debug)]
struct SignalUndefined {}

impl ParseNode for SignalUndefined {
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        (
            String::new(),
            vec![(String::new(), String::new(), 0, ParseStatus::Error)],
        )
    }
    fn new(_data: &[u8]) -> Self {
        SignalUndefined {}
    }
}

#[allow(dead_code)]
// code 0x01
struct CommandRejectRsp {
    reason: u16,
    reason_data: Vec<u8>,
}

#[allow(dead_code)]
// code 0x02
struct ConnectionReq {
    psm: u16,
    source_cid: u16,
}

#[allow(dead_code)]
// code 0x03
struct ConnectionRsp {
    destination_cid: u16,
    source_cid: u16,
    result: u16,
    status: u16,
}

#[allow(dead_code)]
// code 0x04
struct ConfigurationReq {
    destination_cid: u16,
    flags: u16,
    configuration_option: u32,
}

#[allow(dead_code)]
// code 0x05
struct ConfigurationRsp {
    source_cid: u16,
    flags: u16,
    result: u16,
    config: u16,
}

#[allow(dead_code)]
// code 0x06
struct DisconnectionReq {
    destination_cid: u16,
    source_cid: u16,
}

#[allow(dead_code)]
// code 0x07
struct DisconnectionRsp {
    destination_cid: u16,
    source_cid: u16,
}

#[allow(dead_code)]
// code 0x08
struct EchoReq {
    echo_data: Vec<u8>,
}

#[allow(dead_code)]
// code 0x09
struct EchoRsp {
    echo_data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
// code 0x0A
struct InformationReq {
    info_type: u16,
}

impl ParseNode for InformationReq {
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        let info_type_s = "Info Type";
        let value_s = match self.info_type {
            1 => "Connectionless MTU",
            2 => "Extended features supported",
            3 => "Fixed channels supported",
            _ => "",
        };

        (
            String::from("L2CAP_INFORMATION_REQ"),
            vec![(
                String::from(info_type_s),
                format!("{:#x}({})", self.info_type, value_s),
                2,
                if value_s.len() > 0 {
                    ParseStatus::Ok
                } else {
                    ParseStatus::Error
                },
            )],
        )
    }
    fn new(data: &[u8]) -> Self {
        InformationReq {
            info_type: u16::from_le_bytes(data.try_into().unwrap()),
        }
    }
}

#[allow(dead_code)]
// code 0x0B
struct InformationRsp {
    info_type: u16,
    result: u16,
    info: Vec<u8>,
}

impl ParseNode for InformationRsp {
    fn get_info(&self) -> (String, Vec<(String, String, u8, ParseStatus)>) {
        (
            String::new(),
            vec![(String::new(), String::new(), 0, ParseStatus::Error)],
        )
    }
    fn new(data: &[u8]) -> Self {
        InformationRsp {
            info_type: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            result: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            info: Vec::from(&data[4..]),
        }
    }
}

pub fn parse(data: &[u8], _args: &mut InnerStack) -> Vec<Box<dyn ParseLayer>> {
    let header = L2capHeader::new(data);
    let cid = CID::from_u16(header.channel_id);

    use CID::*;
    let ret = match cid {
        L2capSignalingChannel => {
            let cmd = SignalCommandCode::from_u8(data[4]);

            use SignalCommandCode::*;
            let ret: Box<dyn ParseLayer> = match cmd {
                InformationReqCode => {
                    let signal: SignalCommand<InformationReq> = SignalCommand::new(&data[4..]);
                    Box::new(signal)
                }
                _ => {
                    let signal: SignalCommand<SignalUndefined> = SignalCommand::new(&data[4..]);
                    Box::new(signal)
                }
            };
            ret
        }
        _ => Box::new(L2capDummy {}),
    };

    vec![Box::new(header), ret]
}
