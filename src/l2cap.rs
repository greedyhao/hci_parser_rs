use std::fmt::Debug;
use std::vec;

use crate::format_parse_node;
use crate::InnerStack;
use crate::ParseLayer;
use crate::ParseNode;
use crate::ParseNodeInfo;
use crate::ParseNodeSubInfo;
use crate::ParseStatus;

#[derive(Default, Debug)]
pub struct L2capArg {
    channels: Vec<L2capChannel>,
}

#[derive(Default)]
struct L2capChannel {
    source_cid: u16,
    dest_cid: u16,

    psm: u16,

    local_mtu: u16,
    flush_timeout: u16,
}

impl Debug for L2capChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "L2capChannel {{ source_cid: {:#x}, dest_cid: {:#x}, psm: {:#x}({}), local_mtu:{:#x}, flush_timeout:{:#x}}}",
            self.source_cid,
            self.dest_cid,
            self.psm,
            get_psm_name(self.psm),
            self.local_mtu,
            self.flush_timeout,
        )
    }
}

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
        L2capHeader {
            pdu_length: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            channel_id: u16::from_le_bytes(data[2..4].try_into().unwrap()),
        }
    }
}

impl ParseLayer for L2capHeader {
    fn to_json(&self) -> (String, String) {
        let pdu_length_s = "PDU Length";
        let channel_id_s = "Channel ID";

        let major = format!(
            r#""{}": {{{}, {}"#,
            "L2CAP",
            format_parse_node(pdu_length_s, self.pdu_length, None),
            format_parse_node(
                channel_id_s,
                self.channel_id,
                Some(format!("{}", CID::from_u16(self.channel_id)).as_str())
            )
        );

        let minor = format!(
            r#"{{{}, {}"#,
            format_parse_node(pdu_length_s, "(0,2)", None),
            format_parse_node(channel_id_s, "(2,2)", None)
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

impl<T: ParseNode> SignalCommand<T> {
    fn new(data: &[u8]) -> Self {
        SignalCommand {
            code: data[0],
            identifier: data[1],
            data_length: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            data: T::new(&data[4..]),
        }
    }
}

impl<T: ParseNode> ParseLayer for SignalCommand<T> {
    fn to_json(&self) -> (String, String) {
        let code_s = "Code";
        let identifier_s = "Identifier";
        let data_length_s = "Data Length";
        let info = self.data.get_info();

        let mut major = format!(
            r#", {}, {}, {}"#,
            format_parse_node(code_s, self.code, Some(info.name.as_str())),
            format_parse_node(identifier_s, self.identifier, None),
            format_parse_node(data_length_s, self.data_length, None)
        );

        let mut minor = format!(
            r#", {}, {}, {}"#,
            format_parse_node(code_s, "(0,1)", None),
            format_parse_node(identifier_s, "(1,1)", None),
            format_parse_node(data_length_s, "(2,2)", None)
        );

        let mut without_separator = false;
        let mut cnt = 4;
        for sub in info.sub_info {
            if sub.status == ParseStatus::SubtreeStart {
                without_separator = true;
                major.push_str(format!(r#", "{}": {{"#, sub.key).as_str());
                continue;
            } else if sub.status == ParseStatus::SubtreeEnd {
                major.push_str("}");
                continue;
            }

            sub.append_major_info(&mut major, without_separator);
            sub.append_minor_info(&mut minor, without_separator, cnt);
            without_separator = false;
            cnt += sub.length;
        }

        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

#[derive(Debug)]
struct SignalUndefined {}

impl ParseNode for SignalUndefined {
    fn get_info(&self) -> ParseNodeInfo {
        ParseNodeInfo::new("Undefine".to_string(), vec![])
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

impl ParseNode for ConnectionReq {
    fn get_info(&self) -> ParseNodeInfo {
        let psm_s = "PSM";
        let source_cid_s = "Source CID";

        let psm_name_s = get_psm_name(self.psm);
        ParseNodeInfo::new(
            "L2CAP_CONNECTION_REQ".to_string(),
            vec![
                ParseNodeSubInfo::new(
                    psm_s,
                    self.psm,
                    Some(psm_name_s.as_str()),
                    2,
                    check_parse_status(psm_name_s.as_str()),
                ),
                ParseNodeSubInfo::new(source_cid_s, self.source_cid, None, 2, ParseStatus::Ok),
            ],
        )
    }
    fn new(data: &[u8]) -> Self {
        ConnectionReq {
            psm: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            source_cid: u16::from_le_bytes(data[2..4].try_into().unwrap()),
        }
    }
}

#[allow(dead_code)]
// code 0x03
struct ConnectionRsp {
    dest_cid: u16,
    source_cid: u16,
    result: u16,
    status: u16,
}

impl ParseNode for ConnectionRsp {
    fn get_info(&self) -> ParseNodeInfo {
        let dest_cid_s = "Destination CID";
        let source_cid_s = "Source CID";
        let result_s = "Result";
        let status_s = "Status";

        let result_name_s = match self.result {
            0x0000 => "Connection Accepted",
            0x0001 => "Connection pending",
            0x0002 => "Connection refused - PSM not supported",
            0x0003 => "Connection refused - security block",
            0x0004 => "Connection refused - no resources available",
            0x0006 => "Connection refused - invalid Source CID",
            0x0007 => "Connection refused - Source CID already allocated",
            _ => "",
        };

        let status_name_s = match self.status {
            0x0000 => "No further information available",
            0x0001 => "Authentication pending",
            0x0002 => "Authorization pending",
            _ => "",
        };

        ParseNodeInfo::new(
            "L2CAP_CONNECTION_RSP".to_string(),
            vec![
                ParseNodeSubInfo::new(dest_cid_s, self.dest_cid, None, 2, ParseStatus::Ok),
                ParseNodeSubInfo::new(source_cid_s, self.source_cid, None, 2, ParseStatus::Ok),
                ParseNodeSubInfo::new(
                    result_s,
                    self.result,
                    Some(result_name_s),
                    2,
                    check_parse_status(result_name_s),
                ),
                ParseNodeSubInfo::new(
                    status_s,
                    self.status,
                    Some(status_name_s),
                    2,
                    check_parse_status(status_name_s),
                ),
            ],
        )
    }
    fn new(data: &[u8]) -> Self {
        ConnectionRsp {
            dest_cid: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            source_cid: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            result: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            status: u16::from_le_bytes(data[6..8].try_into().unwrap()),
        }
    }
}

// TODO: 添加剩余的 option
enum ConfigParamOption {
    MTU(u16),
    FlushTimeout(u16),
}

impl ConfigParamOption {
    fn new(option: &[u8]) -> Self {
        let len;
        let param = match option[0] {
            0x01 => {
                len = 2;
                ConfigParamOption::MTU(u16::from_le_bytes(option[2..4].try_into().unwrap()))
            }
            0x02 => {
                len = 2;
                ConfigParamOption::FlushTimeout(u16::from_le_bytes(
                    option[2..4].try_into().unwrap(),
                ))
            }
            _ => panic!("Unknown config param option"),
        };

        if len != option[1] {
            panic!("Config param option length mismatch");
        }
        param
    }

    fn get_option_len(&self) -> u8 {
        match self {
            ConfigParamOption::MTU(_) => 2,
            ConfigParamOption::FlushTimeout(_) => 2,
        }
    }

    fn get_subinfo(&self) -> Vec<ParseNodeSubInfo> {
        let option_type_s = "Option Type";
        let option_length_s = "Option Length";
        match self {
            ConfigParamOption::MTU(mtu) => {
                vec![
                    ParseNodeSubInfo::new(
                        option_type_s,
                        "MAXIMUM TRANSMISSION UNIT (MTU)",
                        None,
                        1,
                        ParseStatus::Ok,
                    ),
                    ParseNodeSubInfo::new(
                        option_length_s,
                        self.get_option_len(),
                        None,
                        1,
                        ParseStatus::Ok,
                    ),
                    ParseNodeSubInfo::new("MTU", mtu, None, 2, ParseStatus::Ok),
                ]
            }
            ConfigParamOption::FlushTimeout(flush_timeout) => {
                vec![
                    ParseNodeSubInfo::new(option_type_s, "FLUSH TIMEOUT", None, 1, ParseStatus::Ok),
                    ParseNodeSubInfo::new(
                        option_length_s,
                        self.get_option_len(),
                        None,
                        1,
                        ParseStatus::Ok,
                    ),
                    ParseNodeSubInfo::new("FLUSH TIMEOUT", flush_timeout, None, 2, ParseStatus::Ok),
                ]
            }
        }
    }
}

impl Debug for ConfigParamOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigParamOption::MTU(mtu) => write!(f, r#""MTU":"{:#x}""#, mtu),
            ConfigParamOption::FlushTimeout(flush_timeout) => {
                write!(f, r#""Flush Timeout":"{:#x}"#, flush_timeout)
            }
        }
    }
}

#[allow(dead_code)]
// code 0x04
struct ConfigurationReq {
    dest_cid: u16,
    flags: u16,
    configuration_option: Option<ConfigParamOption>,
}

impl ParseNode for ConfigurationReq {
    fn get_info(&self) -> ParseNodeInfo {
        let dest_cid_s = "Destination CID";
        let flags_s = "Flags";
        let configuration_option_s = "Configuration Option";

        let mut ret = ParseNodeInfo::new(
            "L2CAP_CONFIGURATION_REQ".to_string(),
            vec![
                ParseNodeSubInfo::new(dest_cid_s, self.dest_cid, None, 2, ParseStatus::Ok),
                // TODO: flag 检查与解析
                ParseNodeSubInfo::new(flags_s, self.flags, None, 2, ParseStatus::Ok),
            ],
        );

        // TODO:
        if self.configuration_option.is_some() {
            let option = self.configuration_option.as_ref().unwrap();
            let start = ParseNodeSubInfo::new(
                configuration_option_s,
                "",
                None,
                0,
                ParseStatus::SubtreeStart,
            );
            ret.sub_info.push(start);
            for option in option.get_subinfo() {
                ret.sub_info.push(option);
            }
            let end = ParseNodeSubInfo::new("", "", None, 0, ParseStatus::SubtreeEnd);
            ret.sub_info.push(end);
        }
        ret
    }
    fn new(data: &[u8]) -> Self {
        let option = if data.len() > 4 {
            let option = ConfigParamOption::new(&data[4..]);
            Some(option)
        } else {
            None
        };
        ConfigurationReq {
            dest_cid: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            flags: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            configuration_option: option,
        }
    }
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
    dest_cid: u16,
    source_cid: u16,
}

#[allow(dead_code)]
// code 0x07
struct DisconnectionRsp {
    dest_cid: u16,
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
    fn get_info(&self) -> ParseNodeInfo {
        let info_type_s = "Info Type";
        let info_type_name_s = match self.info_type {
            1 => "Connectionless MTU",
            2 => "Extended features supported",
            3 => "Fixed channels supported",
            _ => "",
        };

        ParseNodeInfo::new(
            "L2CAP_INFORMATION_REQ".to_string(),
            vec![ParseNodeSubInfo::new(
                info_type_s,
                self.info_type,
                Some(info_type_name_s),
                2,
                check_parse_status(info_type_name_s),
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
    fn get_info(&self) -> ParseNodeInfo {
        ParseNodeInfo::new(
            "L2CAP_INFORMATION_RSP".to_string(),
            vec![ParseNodeSubInfo::new("", "", None, 0, ParseStatus::Error)],
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

pub fn parse(data: &[u8], args: &mut InnerStack) -> Vec<Box<dyn ParseLayer>> {
    let header = L2capHeader::new(data);
    let cid = CID::from_u16(header.channel_id);

    use CID::*;
    let ret = match cid {
        L2capSignalingChannel => {
            let cmd = SignalCommandCode::from_u8(data[4]);

            use SignalCommandCode::*;
            let ret: Box<dyn ParseLayer> = match cmd {
                ConnectionReqCode => {
                    let signal: SignalCommand<ConnectionReq> = SignalCommand::new(&data[4..]);
                    let mut channel = L2capChannel::default();
                    channel.source_cid = signal.data.source_cid;
                    channel.psm = signal.data.psm;
                    args.l2cap_arg.channels.push(channel);
                    Box::new(signal)
                }
                ConnectionRspCode => {
                    let signal: SignalCommand<ConnectionRsp> = SignalCommand::new(&data[4..]);
                    for channel in &mut args.l2cap_arg.channels {
                        if channel.source_cid == signal.data.source_cid {
                            channel.dest_cid = signal.data.dest_cid;
                        }
                    }
                    Box::new(signal)
                }
                ConfigurationReqCode => {
                    let signal: SignalCommand<ConfigurationReq> = SignalCommand::new(&data[4..]);
                    use ConfigParamOption::*;
                    for channel in &mut args.l2cap_arg.channels {
                        if channel.dest_cid == signal.data.dest_cid {
                            match signal.data.configuration_option {
                                Some(MTU(mtu)) => {
                                    channel.local_mtu = mtu;
                                }
                                _ => {}
                            }
                        }
                    }
                    Box::new(signal)
                }
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

fn check_parse_status(str: &str) -> ParseStatus {
    if str.len() > 0 {
        ParseStatus::Ok
    } else {
        ParseStatus::Error
    }
}

fn get_psm_name(psm: u16) -> String {
    let psm_name = match psm {
        0x0001 => "SDP",
        0x0003 => "RFCOMM",
        0x0005 => "TCS-BIN",
        0x0007 => "TCS-BIN-CORDLESS",
        0x000F => "BNEP",
        0x0011 => "HID_Control",
        0x0013 => "HID_Interrupt",
        0x0015 => "UPnP",
        0x0017 => "AVCTP",
        0x0019 => "AVDTP",
        0x001B => "AVCTP_Browsing",
        0x001D => "UDI_C-Plane",
        0x001F => "ATT",
        0x0021 => "3DSP",
        0x0023 => "LE_PSM_IPSP",
        0x0025 => "OTS",
        0x0027 => "EATT",
        _ => "",
    };
    psm_name.to_string()
}
