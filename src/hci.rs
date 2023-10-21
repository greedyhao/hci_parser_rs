use crate::l2cap::L2CAP;
use crate::HostStack;
use crate::ParseNode;
use crate::ParseNodeA;
use crate::ParseNodeOpt;
use crate::ParseNodeOptA;

use crate::ParseBitsNode;
use crate::ParseBytesNode;

#[derive(Debug, PartialEq)]
pub enum HciPacket {
    Undefined,
    Cmd(Option<HciCmd>),
    Acl(Option<HciAcl>),
    Sco,
    Evt(Option<HciEvt>),
    Iso,
}

impl ParseNode for HciPacket {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Self {
        let packet_type = data[0];
        let data = &data[1..];
        match packet_type {
            1 => HciPacket::Cmd(HciCmd::new(data, args)),
            2 => HciPacket::Acl(HciAcl::new(data, args)),
            3 => HciPacket::Sco,
            4 => HciPacket::Evt(HciEvt::new(data, args)),
            5 => HciPacket::Iso,
            _ => HciPacket::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let start_byte = start_byte + 1;
        match self {
            HciPacket::Cmd(pkg) => pkg
                .is_some()
                .then(|| pkg.as_ref().unwrap().as_json(start_byte)),
            HciPacket::Acl(pkg) => pkg
                .is_some()
                .then(|| pkg.as_ref().unwrap().as_json(start_byte)),
            HciPacket::Evt(pkg) => pkg
                .is_some()
                .then(|| pkg.as_ref().unwrap().as_json(start_byte)),
            _ => None,
        }
        .unwrap_or("".to_string())
    }
}

#[derive(Debug, PartialEq)]
pub struct HciCmd {
    opcode: u16,
    param_len: u8,
    param: HciCmdParam,
}

impl ParseNodeOpt for HciCmd {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 3 {
            None
        } else {
            let opcode = u16::from_le_bytes([data[0], data[1]]);
            let param_len = data[2];
            let param = HciCmdParam::new(data, args, opcode);
            Some(HciCmd {
                opcode,
                param_len,
                param,
            })
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let ocf = opcode_to_ogf(self.opcode);
        let ogf = opcode_to_ocf(self.opcode);
        let ocf_s = ParseBitsNode::new(start_byte, 2, 0, 10).format(
            "Opcode Command Field (OCF)",
            ocf,
            self.param.get_ocf_name(),
            "",
        );
        let ogf_s = ParseBitsNode::new(start_byte + 1, 1, 10, 6).format(
            "Opcode Group Field (OGF)",
            ogf,
            self.param.get_ogf_name(),
            "",
        );
        let param_len_s = ParseBytesNode::new(start_byte + 2, 1).format(
            "Parameter Total Length",
            self.param_len,
            "",
            "",
        );
        format!(r#""Opcode": {{{}, {}}}, {}"#, ogf_s, ocf_s, param_len_s)
    }
}

#[derive(Debug, PartialEq)]
enum HciCmdParam {
    Undefined,
    LinkControl(OgfLinkControl),
    LinkPolicy,
    ControllerAndBaseband(OgfControllerAndBaseband),
    InformationalParameters,
    StatusParameters,
    Testing,
    LeController,
}

impl HciCmdParam {
    fn get_ogf_name(&self) -> &'static str {
        match self {
            HciCmdParam::LinkControl(_) => "Link Control",
            HciCmdParam::LinkPolicy => "Link Policy",
            HciCmdParam::ControllerAndBaseband(_) => "Controller & Baseband",
            HciCmdParam::InformationalParameters => "Informational Parameters",
            HciCmdParam::StatusParameters => "Status Parameters",
            HciCmdParam::Testing => "Testing",
            HciCmdParam::LeController => "LE Controller",
            HciCmdParam::Undefined => "Undefined",
        }
    }

    fn get_ocf_name(&self) -> &'static str {
        match self {
            HciCmdParam::LinkControl(cmd) => cmd.get_ocf_name(),
            HciCmdParam::ControllerAndBaseband(cmd) => cmd.get_ocf_name(),
            _ => "",
        }
    }
}

impl ParseNodeA<u16> for HciCmdParam {
    fn new(data: &[u8], args: Option<&mut HostStack>, opcode: u16) -> Self {
        let ogf = opcode_to_ogf(opcode);
        match ogf {
            1 => HciCmdParam::LinkControl(OgfLinkControl::new(data, args, opcode)),
            2 => HciCmdParam::LinkPolicy,
            3 => HciCmdParam::ControllerAndBaseband(OgfControllerAndBaseband::new(
                data, args, opcode,
            )),
            4 => HciCmdParam::InformationalParameters,
            5 => HciCmdParam::StatusParameters,
            6 => HciCmdParam::Testing,
            8 => HciCmdParam::LeController,
            _ => HciCmdParam::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let body = match self {
            HciCmdParam::LinkControl(cmd) => cmd.as_json(start_byte),
            HciCmdParam::LinkPolicy => "".to_string(),
            HciCmdParam::ControllerAndBaseband(cmd) => cmd.as_json(start_byte),
            HciCmdParam::InformationalParameters => "".to_string(),
            HciCmdParam::StatusParameters => "".to_string(),
            HciCmdParam::Testing => "".to_string(),
            HciCmdParam::LeController => "".to_string(),
            HciCmdParam::Undefined => "".to_string(),
        };
        format!(r#""HCI": {{{}}}"#, body)
    }
}

#[derive(Debug, PartialEq)]
enum OgfLinkControl {
    Undefined,
    Inquiry(Option<OcfInquiry>),
}

impl OgfLinkControl {
    fn get_ocf_name(&self) -> &'static str {
        match self {
            OgfLinkControl::Inquiry(_) => "Inquiry",
            _ => "",
        }
    }
}

impl ParseNodeA<u16> for OgfLinkControl {
    fn new(data: &[u8], args: Option<&mut HostStack>, opcode: u16) -> Self {
        let ocf = opcode_to_ogf(opcode);
        match ocf {
            1 => OgfLinkControl::Inquiry(OcfInquiry::new(data, args)),
            _ => OgfLinkControl::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            OgfLinkControl::Inquiry(cmd) => cmd
                .is_some()
                .then(|| cmd.as_ref().unwrap().as_json(start_byte)),
            _ => None,
        }
        .unwrap_or("".to_string())
    }
}

#[derive(Debug, PartialEq)]
struct OcfInquiry {
    lap: u32,
    inquiry_len: u8,
    num_resp: u8,
}

impl ParseNodeOpt for OcfInquiry {
    fn new(data: &[u8], _args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 5 {
            None
        } else {
            let lap = data[0] as u32 | (data[1] as u32) << 8 | (data[2] as u32) << 16;
            let inquiry_len = data[3];
            let num_resp = data[4];
            Some(OcfInquiry {
                lap,
                inquiry_len,
                num_resp,
            })
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let lap_s = ParseBytesNode::new(start_byte, 3).format("LAP", self.lap, "", "");
        let inquiry_len_s = ParseBytesNode::new(start_byte + 3, 1).format(
            "Inquiry Length",
            self.inquiry_len,
            "",
            "",
        );
        let num_resp_s = ParseBytesNode::new(start_byte + 4, 1).format(
            "Number of Responses",
            self.num_resp,
            "",
            "",
        );
        format!(r#"{}, {}, {}"#, lap_s, inquiry_len_s, num_resp_s)
    }
}

#[derive(Debug, PartialEq)]
enum OgfControllerAndBaseband {
    Undefined,
    Reset(Option<OcfReset>),
}

impl OgfControllerAndBaseband {
    fn get_ocf_name(&self) -> &'static str {
        match self {
            OgfControllerAndBaseband::Reset(_) => "Reset",
            _ => "",
        }
    }
}

impl ParseNodeA<u16> for OgfControllerAndBaseband {
    fn new(data: &[u8], args: Option<&mut HostStack>, opcode: u16) -> Self {
        let ocf = opcode_to_ogf(opcode);
        match ocf {
            3 => OgfControllerAndBaseband::Reset(OcfReset::new(data, args)),
            _ => OgfControllerAndBaseband::Undefined,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            OgfControllerAndBaseband::Reset(cmd) => cmd
                .is_some()
                .then(|| cmd.as_ref().unwrap().as_json(start_byte)),
            _ => None,
        }
        .unwrap_or("".to_string())
    }
}

#[derive(Debug, PartialEq)]
struct OcfReset {}

impl ParseNodeOpt for OcfReset {
    fn new(_data: &[u8], _args: Option<&mut HostStack>) -> Option<Self> {
        Some(OcfReset {})
    }
    fn as_json(&self, start_byte: u8) -> String {
        ParseBytesNode::new(start_byte, 0).format("Reset", "", "", "")
    }
}

#[derive(Debug, PartialEq)]
pub struct HciAcl {
    handle: u16,
    pb_flag: u8,
    bc_flag: u8,
    data_len: u16,
    data: Option<L2CAP>,
}

impl ParseNodeOpt for HciAcl {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 4 {
            None
        } else {
            let handle = u16::from_le_bytes(data[0..2].try_into().unwrap());
            Some(HciAcl {
                handle: handle & 0xfff,
                pb_flag: ((handle >> 12) & 0x3) as u8,
                bc_flag: (handle >> 14) as u8,
                data_len: u16::from_le_bytes(data[2..4].try_into().unwrap()),
                data: L2CAP::new(&data[4..], args),
            })
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let handle_s =
            ParseBitsNode::new(start_byte, 2, 0, 12).format("Handle", self.handle, "", "");
        let pb_flag_s =
            ParseBitsNode::new(start_byte + 1, 1, 12, 2).format("PB Flag", self.pb_flag, "", "");
        let bc_flag_s =
            ParseBitsNode::new(start_byte + 1, 1, 14, 2).format("BC Flag", self.bc_flag, "", "");
        let data_len_s = ParseBytesNode::new(start_byte + 2, 2).format(
            "Data Totlal Length",
            self.data_len,
            "",
            "",
        );
        let data_s = self
            .data
            .is_some()
            .then(|| self.data.as_ref().unwrap().as_json(start_byte + 4))
            .unwrap_or("".to_string());
        format!(
            r#""ACL": {{{}, {}, {}, {}, {}}}"#,
            handle_s, pb_flag_s, bc_flag_s, data_len_s, data_s
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct HciEvt {
    code: u8,
    len: u8,
    param: Option<HciEvtParam>,
}

impl ParseNodeOpt for HciEvt {
    fn new(data: &[u8], args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 2 {
            None
        } else {
            let code = data[0];
            let len = data[1];
            Some(HciEvt {
                code,
                len,
                param: HciEvtParam::new(&data[2..], args, code),
            })
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let code_name_s = match self.code {
            0x0e => "HCI_Command_Complete",
            _ => "Unknown",
        };

        let code_s =
            ParseBytesNode::new(start_byte, 1).format("Event Code", self.code, code_name_s, "");
        let len_s = ParseBytesNode::new(start_byte + 1, 1).format(
            "Parameter Total Length",
            self.len,
            "",
            "",
        );
        let param_s = self
            .param
            .is_some()
            .then(|| self.param.as_ref().unwrap().as_json(start_byte + 2))
            .unwrap_or("".to_string());
        format!(r#""EVT": {{{}, {}, {}}}"#, code_s, len_s, param_s)
    }
}

#[derive(Debug, PartialEq)]
enum HciEvtParam {
    Undefined,
    CommandComplete(Option<EvtCommandComplete>),
}

impl ParseNodeOptA<u8> for HciEvtParam {
    fn new(data: &[u8], args: Option<&mut HostStack>, code: u8) -> Option<Self> {
        let ret = match code {
            0x0e => HciEvtParam::CommandComplete(EvtCommandComplete::new(data, args)),
            _ => HciEvtParam::Undefined,
        };
        Some(ret)
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            HciEvtParam::CommandComplete(evt) => evt
                .is_some()
                .then(|| evt.as_ref().unwrap().as_json(start_byte)),
            _ => None,
        }
        .unwrap_or("".to_string())
    }
}

#[derive(Debug, PartialEq)]
struct EvtCommandComplete {
    num_hci_command_packets: u8,
    command_opcode: u16,
    // return Depends on command
}

impl ParseNodeOpt for EvtCommandComplete {
    fn new(data: &[u8], _args: Option<&mut HostStack>) -> Option<Self> {
        if data.len() < 3 {
            None
        } else {
            Some(EvtCommandComplete {
                num_hci_command_packets: data[0],
                command_opcode: u16::from_le_bytes([data[1], data[2]]),
            })
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let mut data = Vec::from(self.command_opcode.to_le_bytes());
        data.push(3);
        let cmd = HciCmd::new(&data, None);
        let num_hci_command_packets_s = ParseBytesNode::new(start_byte, 1).format(
            "Num_HCI_Command_Packets",
            self.num_hci_command_packets,
            "",
            "",
        );
        let opcode_s =
            ParseBytesNode::new(start_byte + 1, 2).format("Opcode", self.command_opcode, "", "");
        let opcode_ogf_s = ParseBytesNode::new(start_byte + 2, 1).format(
            "Opcode Group Field (OGF)",
            opcode_to_ogf(self.command_opcode),
            cmd.is_some()
                .then(|| cmd.as_ref().unwrap().param.get_ogf_name())
                .unwrap_or(""),
            "",
        );
        let opcode_ocf_s = ParseBytesNode::new(start_byte + 1, 2).format(
            "Opcode Command Field (OCF)",
            opcode_to_ocf(self.command_opcode),
            cmd.is_some()
                .then(|| cmd.as_ref().unwrap().param.get_ocf_name())
                .unwrap_or(""),
            "",
        );
        format!(
            "{}, Command_Opcode: {{{}, {}, {}}}",
            num_hci_command_packets_s, opcode_s, opcode_ogf_s, opcode_ocf_s
        )
    }
}

pub fn parse(data: &[u8], args: &mut HostStack) -> String {
    let ret = HciPacket::new(data, Some(args));
    println!("ret={:?}\n", ret);

    ret.as_json(0)
}

fn opcode_to_ogf(opcode: u16) -> u8 {
    (opcode & 0x3ff) as u8
}

fn opcode_to_ocf(opcode: u16) -> u8 {
    (opcode >> 10) as u8
}

#[cfg(test)]
mod tests {
    // use crate::str_to_array;

    // use super::*;
    // #[test]
    // fn hci_cmd_reset_test() {
    //     let mut args = HostStack::new();
    //     let cmd = str_to_array("01 03 0c 00");
    //     let res = HciPacket::new(&cmd, &mut args);
    //     let expect = HciPacket::Cmd(HciCmd {
    //         opcode: 0x0c03,
    //         param_len: 0,
    //         param: HciCmdParam::ControllerAndBaseband(OgfControllerAndBaseband::Reset(OcfReset {})),
    //     });
    //     assert_eq!(res, expect);
    // }

    // #[test]
    // fn hci_evt_0x0e_test() {
    //     let mut args = HostStack::new();
    //     let evt = str_to_array("04 0e 04 05 03 0c 00");
    //     let res = HciPacket::new(&evt, &mut args);
    //     let expect = HciPacket::Evt(HciEvt {
    //         code: 0x0e,
    //         len: 4,
    //         param: HciEvtParam::CommandComplete(EvtCommandComplete {
    //             num_hci_command_packets: 5,
    //             command_opcode: 0x0c03,
    //         }),
    //     });
    //     assert_eq!(res, expect);
    // }
}
