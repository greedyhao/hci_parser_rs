use std::vec;

use crate::l2cap;
use crate::InnerStack;
use crate::ParseLayer;
use crate::ParseNode;
use crate::ParseNodeInfo;
use crate::ParseNodeSubInfo;
use crate::ParseStatus;

#[allow(unused)]
pub enum HciPacket {
    Cmd,
    Acl,
    Sco,
    Evt,
    Iso,
}

#[allow(unused)]
#[repr(u8)]
enum HciCmdOgf {
    NoUse = 0,
    LinkControl = 0x01,
    LinkPolicy,
    ControlAndBaseBand,
    InformationalParameters,
    StatusParameters,
    Testing,
    LeController = 0x08,
}

impl HciCmdOgf {
    fn from_u8(ogf: u8) -> Self {
        use HciCmdOgf::*;
        match ogf {
            0x01 => LinkControl,
            0x02 => LinkPolicy,
            0x03 => ControlAndBaseBand,
            0x04 => InformationalParameters,
            0x05 => StatusParameters,
            0x06 => Testing,
            0x08 => LeController,
            _ => NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmd<T> {
    opcode: u16,
    param_total_len: u8,
    param: T,
}

impl<T: ParseNode> HciCmd<T> {
    fn new(data: &[u8]) -> Self {
        let opcode = data[0] as u16 | (data[1] as u16) << 8;
        let param_total_len = data[2];
        HciCmd {
            opcode,
            param_total_len,
            param: T::new(&data[3..]),
        }
    }
}

impl<T: ParseNode> ParseLayer for HciCmd<T> {
    fn to_json(&self) -> (String, String) {
        let ocf = self.opcode & 0x3FF;
        let ogf = self.opcode >> 10;

        let opcode_s = "Opcode";
        let ocf_s = "OCF";
        let ogf_s = "OGF";
        let command_s = "Command";
        let param_total_len_s = "Parameter_Total_Length";
        let info = self.param.get_info();
        let mut major = format!(
            r#""{}":{{"{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}", "{}":"{}", "{}":"{:#x}""#,
            "HCI",
            opcode_s,
            self.opcode,
            ocf_s,
            ocf,
            ogf_s,
            ogf,
            command_s,
            info.name,
            param_total_len_s,
            self.param_total_len
        );
        let mut minor = format!(
            r#"{{"{}":"(0,2)", "{}":"(0,1)", "{}","(1,1)", "{}":"(0,2)", "{}":"(2,1),0""#,
            opcode_s, ocf_s, ogf_s, command_s, param_total_len_s
        );

        let mut cnt = 3;
        for sub in info.sub_info {
            major.push_str(format!(r#", "{}":"{}""#, sub.key, sub.value).as_str());
            minor.push_str(format!(r#", "{}":"({},{})""#, sub.key, cnt, sub.length).as_str());
            if sub.status != ParseStatus::Ok {
                minor.push_str(format!(r#",{}"#, sub.status as u8).as_str());
            }
            cnt += sub.length;
        }
        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

// Dummy
struct HciParseDummy {}

impl ParseNode for HciParseDummy {
    fn new(_data: &[u8]) -> Self {
        HciParseDummy {}
    }
    fn get_info(&self) -> ParseNodeInfo {
        ParseNodeInfo::new("Dummy".to_string(), vec![])
    }
}

// LinkControl
#[derive(Debug)]
enum HciCmdLinkControl {
    NoUse = 0,
    Inquiry = 1,
}

impl HciCmdLinkControl {
    fn from_u16(ocf: u16) -> Self {
        match ocf {
            1 => HciCmdLinkControl::Inquiry,
            _ => HciCmdLinkControl::NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmdOgf1Inquiry {
    lap: [u8; 3],
    inquiry_length: u8,
    num_responses: u8,
}

impl ParseNode for HciCmdOgf1Inquiry {
    fn new(data: &[u8]) -> Self {
        HciCmdOgf1Inquiry {
            lap: data[0..3].try_into().expect("slice with incorrect length"),
            inquiry_length: data[3],
            num_responses: data[4],
        }
    }
    fn get_info(&self) -> ParseNodeInfo {
        let lap = (self.lap[0] as u32) | (self.lap[1] as u32) << 8 | (self.lap[2] as u32) << 16;
        let lap_check = if lap >= 0x9E8B00 && lap <= 0x9E8B3F {
            ParseStatus::Ok
        } else {
            ParseStatus::Error
        };

        let inquiry_length = self.inquiry_length;
        let inquiry_length_check = if inquiry_length >= 0x1 && inquiry_length <= 0x30 {
            ParseStatus::Ok
        } else {
            ParseStatus::Error
        };

        ParseNodeInfo::new(
            "Inquiry".to_string(),
            vec![
                ParseNodeSubInfo::new("LAP".to_string(), format!("{:#x}", lap), 3, lap_check),
                ParseNodeSubInfo::new(
                    "Inquiry_Length".to_string(),
                    format!("{:#x}", self.inquiry_length),
                    1,
                    inquiry_length_check,
                ),
                ParseNodeSubInfo::new(
                    "Num_Responses".to_string(),
                    format!("{:#x}", self.num_responses),
                    1,
                    ParseStatus::Ok,
                ),
            ],
        )
    }
}

// LinkPolicy

// #[repr(u16)]
// enum HciCmdLinkPolicy {
//     NoUse = 0,
//     HoldMode = 1,
// }

// ControlAndBaseBand
#[repr(u16)]
enum HciCmdControlAndBaseband {
    NoUse = 0,
    // SetEventMask = 1,
    Reset = 3,
    // SetEventFilter = 5,
}

impl HciCmdControlAndBaseband {
    fn from_u16(ocf: u16) -> Self {
        match ocf {
            3 => HciCmdControlAndBaseband::Reset,
            _ => HciCmdControlAndBaseband::NoUse,
        }
    }
}

#[derive(Debug)]
struct HciCmdOgf3Reset {}

impl ParseNode for HciCmdOgf3Reset {
    fn new(_data: &[u8]) -> Self {
        HciCmdOgf3Reset {}
    }
    fn get_info(&self) -> ParseNodeInfo {
        ParseNodeInfo::new("Reset".to_string(), vec![])
    }
}

// InformationalParameters

// #[repr(u16)]
// enum HciCmdInformationalParameters {
//     NoUse = 0,
//     ReadLocalVersionInformation = 1,
// }

// StatusParameters

// #[repr(u16)]
// enum HciCmdStatusParameters {
//     NoUse = 0,
//     ReadFailedContactCounter = 1,
// }

// Testing

// #[repr(u16)]
// enum HciCmdTesting {
//     NoUse = 0,
//     ReadLoopbackMode = 1,
// }

// LeController

// #[repr(u16)]
// enum HciCmdLeController {
//     NoUse = 0,
//     LeSetEventMask = 1,
// }

/// HCI ACL

struct HciAcl {
    /// Handle:[0-11], PB Flag:[12-13], PC Flag:[14-15]
    handle_and_flags: u16,
    data_total_length: u16,
}

impl HciAcl {
    fn new(data: &[u8]) -> Self {
        let handle_and_flags = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let data_total_length = u16::from_le_bytes(data[2..4].try_into().unwrap());
        HciAcl {
            handle_and_flags,
            data_total_length,
        }
    }
}

impl ParseLayer for HciAcl {
    fn to_json(&self) -> (String, String) {
        let handle_s = "Handle";
        let pb_flag_s = "PB Flag";
        let pc_flag_s = "PC Flag";
        let data_total_length_s = "Data Total Length";

        let mut major = format!(
            r#""{}":{{"{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}", "{}":"{:#x}""#,
            "HCI",
            handle_s,
            self.handle_and_flags & 0xfff,
            pb_flag_s,
            (self.handle_and_flags >> 12) & 0x3,
            pc_flag_s,
            self.handle_and_flags >> 14,
            data_total_length_s,
            self.data_total_length
        );
        let mut minor = format!(
            r#"{{"{}":"(0,2)", "{}":"(1,1)", "{}","(1,1)", "{}":"(2,2)""#,
            handle_s, pb_flag_s, pc_flag_s, data_total_length_s
        );

        major.push_str("}");
        minor.push_str("}");
        (major, minor)
    }
}

pub fn parse(
    packet_type: HciPacket,
    data: &[u8],
    args: &mut InnerStack,
) -> Vec<Box<dyn ParseLayer>> {
    use HciPacket::*;
    let node: Vec<Box<dyn ParseLayer>> = match packet_type {
        Cmd => {
            if data.len() < 3 {
                println!("data size err!(less than 3B)");
            }

            let opcode = u16::from_le_bytes(data[0..2].try_into().unwrap());
            let ocf = opcode & 0x3FF;
            let ogf = opcode >> 10;

            let ogf_conv = HciCmdOgf::from_u8(ogf as u8);

            use HciCmdControlAndBaseband::*;
            use HciCmdLinkControl::*;
            use HciCmdOgf::*;

            let ret: Box<dyn ParseLayer> = match ogf_conv {
                LinkControl => {
                    let ocf_conv = HciCmdLinkControl::from_u16(ocf);
                    let ret: Box<dyn ParseLayer> = match ocf_conv {
                        Inquiry => {
                            let cmd: HciCmd<HciCmdOgf1Inquiry> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                        _ => {
                            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                    };
                    ret
                }
                ControlAndBaseBand => {
                    let ocf_conv = HciCmdControlAndBaseband::from_u16(ocf);
                    let ret: Box<dyn ParseLayer> = match ocf_conv {
                        Reset => {
                            let cmd: HciCmd<HciCmdOgf3Reset> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                        _ => {
                            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                            Box::new(cmd)
                        }
                    };
                    ret
                }
                _ => {
                    let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
                    Box::new(cmd)
                }
            };

            vec![ret]
        }
        Acl => {
            if data.len() < 4 {
                println!("data size err!(less than 4B)");
            }
            let acl = HciAcl::new(data);
            let mut ret = l2cap::parse(&data[4..], args);
            ret.insert(0, Box::new(acl));
            ret
        }
        _ => {
            let cmd: HciCmd<HciParseDummy> = HciCmd::new(data);
            vec![Box::new(cmd)]
        }
    };
    node
}

#[cfg(test)]
mod tests {
    #[test]
    fn hci_cmd_ogf3_reset_test() {
        use crate::hci;
        use crate::HciPacket::*;
        use crate::InnerStack;

        let mut args = InnerStack::new();
        let cmd = [0x03, 0x0c, 0x00];
        let res = hci::parse(Cmd, &cmd, &mut args);

        let res = res[0].to_json();
        assert_eq!(
            res.0,
            r#"{"Opcode":"0xc03", "OCF":"0x3", "OGF":"0x3", "Command":"Reset", "Parameter_Total_Length":"0x0"}"#
        );
        assert_eq!(
            res.1,
            r#"{"Opcode":"(0,2)", "OCF":"(0,1)", "OGF","(1,1)", "Command":"(0,2)", "Parameter_Total_Length":"(2,1),0"}"#
        );
    }
}
