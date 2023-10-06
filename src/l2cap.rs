use std::fmt::Debug;

use crate::HostStack;
use crate::ParseNodeWithArgs;

// use crate::ParseBitsNode;
use crate::ParseBytesNode;

#[derive(Default, Debug)]
pub struct L2CAPArg {
    channels: Vec<L2CAPChannel>,
}

#[derive(Default)]
struct L2CAPChannel {
    identifier: u8,
    source_cid: u16,
    dest_cid: u16,

    psm: u16,

    local_mtu: u16,
    remote_mtu: u16,
    flush_timeout: u16,
}

impl Debug for L2CAPChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "L2CAPChannel {{ identifier:{:#x}, source_cid: {:#x}, dest_cid: {:#x}, psm: {:#x}({}), local_mtu:{:#x}, remote_mtu:{:#x}, flush_timeout:{:#x}}}",
            self.identifier,
            self.source_cid,
            self.dest_cid,
            self.psm,
            PSM::fake_new(self.psm).get_name(),
            self.local_mtu,
            self.remote_mtu,
            self.flush_timeout,
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum L2CAP {
    L2CAPB(L2CAPB),
}

impl ParseNodeWithArgs for L2CAP {
    fn new(data: &[u8], args: &mut HostStack) -> Self {
        L2CAP::L2CAPB(L2CAPB::new(data, args))
    }

    fn as_json(&self, start_byte: u8) -> String {
        match self {
            L2CAP::L2CAPB(l2cap) => l2cap.as_json(start_byte),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct L2CAPB {
    pdu_len: u16,
    cid: u16,
    payload: Channel,
}

impl ParseNodeWithArgs for L2CAPB {
    fn new(data: &[u8], args: &mut HostStack) -> Self {
        let pdu_len = u16::from_le_bytes([data[0], data[1]]);
        let cid = u16::from_le_bytes([data[2], data[3]]);
        let payload = Channel::new(&data[4..], args, cid);
        L2CAPB {
            pdu_len,
            cid,
            payload,
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let pdu_len_s =
            ParseBytesNode::new(start_byte, 2).format("PDU Length", self.pdu_len, "", "");
        let cid_s = ParseBytesNode::new(start_byte + 2, 2).format("Channel ID", self.cid, "", "");
        let payload_s = self.payload.as_json(start_byte + 4);

        format!("{}, {}, {}", pdu_len_s, cid_s, payload_s)
    }
}

#[derive(Debug, PartialEq)]
enum Channel {
    Undefined,
    L2CAPSignalingChannel(L2CAPSignaling),
    ConnetionlessChannel,
    BrEdrSecurityManager, // 7
    DynamicallyAllocated(PSM), // 0x40-0x7f
}

impl Channel {
    fn new(data: &[u8], args: &mut HostStack, cid: u16) -> Self {
        match cid {
            1 => Channel::L2CAPSignalingChannel(L2CAPSignaling::new(data, args)),
            2 => Channel::ConnetionlessChannel,
            7 => Channel::BrEdrSecurityManager,
            _ => {
                if cid >= 0x40 && cid <= 0x7f {
                    let channels = &mut args.l2cap_arg.channels;
                    for channel in channels.iter() {
                        if channel.dest_cid == cid {
                            return Channel::DynamicallyAllocated(PSM::new(data, channel.psm));
                        }
                    }
                    Channel::DynamicallyAllocated(PSM::new(data, 0))
                } else {
                    Channel::Undefined
                }
            }
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        match self {
            Channel::L2CAPSignalingChannel(l2cap_signaling) => l2cap_signaling.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

trait SignalNode {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self;
    fn as_json(&self, start_byte: u8) -> String;
}

#[derive(Debug, PartialEq)]
struct L2CAPSignaling {
    code: u8,
    identifier: u8,
    data_length: u16,
    data: L2CAPSigData,
}

impl ParseNodeWithArgs for L2CAPSignaling {
    fn new(data: &[u8], args: &mut HostStack) -> Self {
        let code = data[0];
        let identifier = data[1];
        let data_length = u16::from_le_bytes([data[2], data[3]]);
        let data = L2CAPSigData::new(data, args, identifier);
        L2CAPSignaling {
            code,
            identifier,
            data_length,
            data,
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let code_s = ParseBytesNode::new(start_byte, 1).format("Code", self.code, "", "");
        let identifier_s =
            ParseBytesNode::new(start_byte + 1, 1).format("Identifier", self.identifier, "", "");
        let data_length_s =
            ParseBytesNode::new(start_byte + 2, 2).format("Data Length", self.data_length, "", "");
        let data_s = self.data.as_json(start_byte);
        format!(
            r#"{}, {}, {}, {}"#,
            code_s, identifier_s, data_length_s, data_s
        )
    }
}

#[derive(Debug, PartialEq)]
enum L2CAPSigData {
    Undefined,
    CommandRejectRspCode,
    ConnectionReqCode(SignalConnReq),
    ConnectionRspCode(SignalConnRsp),
    ConfigurationReqCode(SignalConfReq),
    ConfigurationRspCode(SignalConfRsp),
    DisconnectionReqCode,
    DisconnectionRspCode,
    EchoReqCode,
    EchoRspCode,
    InformationReqCode(SignalInfoReq),
    InformationRspCode,
}

impl SignalNode for L2CAPSigData {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self {
        let code = data[0];
        let data = &data[4..];
        match code {
            0x01 => L2CAPSigData::CommandRejectRspCode,
            0x02 => L2CAPSigData::ConnectionReqCode(SignalConnReq::new(data, args, id)),
            0x03 => L2CAPSigData::ConnectionRspCode(SignalConnRsp::new(data, args, id)),
            0x04 => L2CAPSigData::ConfigurationReqCode(SignalConfReq::new(data, args, id)),
            0x05 => L2CAPSigData::ConfigurationRspCode(SignalConfRsp::new(data, args, id)),
            0x06 => L2CAPSigData::DisconnectionReqCode,
            0x07 => L2CAPSigData::DisconnectionRspCode,
            0x08 => L2CAPSigData::EchoReqCode,
            0x09 => L2CAPSigData::EchoRspCode,
            0x0a => L2CAPSigData::InformationReqCode(SignalInfoReq::new(data, args, id)),
            0x0b => L2CAPSigData::InformationRspCode,
            _ => L2CAPSigData::Undefined,
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let start_byte = start_byte + 4;
        match self {
            L2CAPSigData::ConnectionReqCode(signal) => signal.as_json(start_byte),
            L2CAPSigData::ConnectionRspCode(signal) => signal.as_json(start_byte),
            L2CAPSigData::ConfigurationReqCode(signal) => signal.as_json(start_byte),
            L2CAPSigData::ConfigurationRspCode(signal) => signal.as_json(start_byte),
            L2CAPSigData::InformationReqCode(signal) => signal.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug, PartialEq)]
// code 0x02
struct SignalConnReq {
    psm: u16,
    source_cid: u16,
}

impl SignalNode for SignalConnReq {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self {
        let sig = SignalConnReq {
            psm: u16::from_le_bytes([data[0], data[1]]),
            source_cid: u16::from_le_bytes([data[2], data[3]]),
        };

        let channels = &mut args.l2cap_arg.channels;
        let mut is_contain = false;
        for channel in channels.iter() {
            if channel.source_cid == sig.source_cid {
                is_contain = true;
                break;
            }
        }
        if !is_contain {
            let mut channel = L2CAPChannel::default();
            channel.identifier = id;
            channel.psm = sig.psm;
            channel.source_cid = sig.source_cid;
            channels.push(channel);
        }
        sig
    }
    fn as_json(&self, start_byte: u8) -> String {
        let psm_s = ParseBytesNode::new(start_byte, 2).format(
            "PSM",
            self.psm,
            &PSM::fake_new(self.psm).get_name(),
            "",
        );
        let source_cid_s =
            ParseBytesNode::new(start_byte + 2, 2).format("Source CID", self.source_cid, "", "");
        format!("{}, {}", psm_s, source_cid_s)
    }
}

#[derive(Debug, PartialEq)]
// code 0x03
struct SignalConnRsp {
    dest_cid: u16,
    source_cid: u16,
    result: u16,
    status: u16,
}

impl SignalNode for SignalConnRsp {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self {
        let sig = SignalConnRsp {
            dest_cid: u16::from_le_bytes([data[0], data[1]]),
            source_cid: u16::from_le_bytes([data[2], data[3]]),
            result: u16::from_le_bytes([data[4], data[5]]),
            status: u16::from_le_bytes([data[6], data[7]]),
        };

        let channels = &mut args.l2cap_arg.channels;
        for channel in channels.iter_mut() {
            if channel.source_cid == sig.source_cid {
                channel.dest_cid = sig.dest_cid;
                channel.identifier = id;
            }
        }
        sig
    }

    fn as_json(&self, start_byte: u8) -> String {
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

        let dest_cid_s =
            ParseBytesNode::new(start_byte, 2).format("Destination CID", self.dest_cid, "", "");
        let source_cid_s =
            ParseBytesNode::new(start_byte + 2, 2).format("Source CID", self.source_cid, "", "");
        let result_s =
            ParseBytesNode::new(start_byte + 4, 2).format("Result", self.result, result_name_s, "");
        let status_s =
            ParseBytesNode::new(start_byte + 6, 2).format("Status", self.status, status_name_s, "");

        format!(
            "{}, {}, {}, {}",
            dest_cid_s, source_cid_s, result_s, status_s
        )
    }
}

#[derive(Debug, PartialEq)]
// code 0x04
struct SignalConfReq {
    dest_cid: u16,
    flags: u16,
    option: Option<ConfigOption>,
}

impl SignalNode for SignalConfReq {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self {
        let sig = SignalConfReq {
            dest_cid: u16::from_le_bytes([data[0], data[1]]),
            flags: u16::from_le_bytes([data[2], data[3]]),
            option: Some(ConfigOption::new(&data[4..])),
        };

        let channels = &mut args.l2cap_arg.channels;
        for channel in channels.iter_mut() {
            if sig.dest_cid == channel.dest_cid {
                let data = sig.option.as_ref();
                if let Some(option) = data {
                    if let ConfigOptionData::MTU(option) = &option.data {
                        channel.identifier = id;
                        channel.local_mtu = option.mtu;
                    }
                }
            } else if sig.dest_cid == channel.source_cid {
                let data = sig.option.as_ref();
                if let Some(option) = data {
                    if let ConfigOptionData::MTU(option) = &option.data {
                        channel.identifier = id;
                        channel.remote_mtu = option.mtu;
                    }
                }
            }
        }
        sig
    }

    fn as_json(&self, start_byte: u8) -> String {
        let dest_cid_s =
            ParseBytesNode::new(start_byte, 2).format("Destination CID", self.dest_cid, "", "");
        let flags_s = ParseBytesNode::new(start_byte + 2, 2).format("Flags", self.flags, "", "");
        let mut json = format!("{}, {}", dest_cid_s, flags_s);
        if let Some(option) = &self.option {
            json.push_str(", ");
            json.push_str(option.as_json(start_byte + 4).as_str());
        }

        json
    }
}

#[derive(Debug, PartialEq)]
// code 0x05
struct SignalConfRsp {
    source_cid: u16,
    flags: u16,
    result: u16,
    option: Option<ConfigOption>,
}

impl SignalNode for SignalConfRsp {
    fn new(data: &[u8], args: &mut HostStack, id: u8) -> Self {
        let option = if data.len() > 6 {
            Some(ConfigOption::new(&data[6..]))
        } else {
            None
        };
        let sig = SignalConfRsp {
            source_cid: u16::from_le_bytes([data[0], data[1]]),
            flags: u16::from_le_bytes([data[2], data[3]]),
            result: u16::from_le_bytes([data[4], data[5]]),
            option,
        };

        let channels = &mut args.l2cap_arg.channels;
        for channel in channels.iter_mut() {
            if sig.source_cid == channel.dest_cid {
                let data = sig.option.as_ref();
                if let Some(option) = data {
                    if let ConfigOptionData::MTU(option) = &option.data {
                        channel.identifier = id;
                        channel.remote_mtu = option.mtu;
                    }
                }
            }
        }

        sig
    }
    fn as_json(&self, start_byte: u8) -> String {
        let result_name_s = match self.result {
            0x0000 => "Success",
            0x0001 => "Failure - unacceptable parameters",
            0x0002 => "Failure - rejected (no reason provided)",
            0x0003 => "Failure - unknown options",
            0x0004 => "Pending",
            0x0005 => "Failure - flow spec rejected",
            _ => "Reserved for future use",
        };
        let dest_cid_s =
            ParseBytesNode::new(start_byte, 2).format("Destination CID", self.source_cid, "", "");
        let flags_s = ParseBytesNode::new(start_byte + 2, 2).format("Flags", self.flags, "", "");
        let result_s =
            ParseBytesNode::new(start_byte + 4, 2).format("Result", self.result, result_name_s, "");

        let mut json = format!("{}, {}, {}", dest_cid_s, flags_s, result_s);
        if let Some(option) = &self.option {
            json.push_str(", ");
            json.push_str(option.as_json(start_byte + 6).as_str());
        }
        json
    }
}

#[derive(Debug, PartialEq)]
struct SignalInfoReq {
    info_type: u16,
}

impl SignalNode for SignalInfoReq {
    fn new(data: &[u8], _args: &mut HostStack, _id: u8) -> Self {
        SignalInfoReq {
            info_type: u16::from_le_bytes([data[0], data[1]]),
        }
    }
    fn as_json(&self, start_byte: u8) -> String {
        let info_type_s =
            ParseBytesNode::new(start_byte, 2).format("Info Type", self.info_type, "", "");
        format!("{}", info_type_s)
    }
}

#[derive(Debug, PartialEq)]
enum ConfigOptionData {
    Undefined,
    MTU(ConfigOptionMTU),
    FlushTimeout,
    QOS,
    RetransmissionAndFlowControl,
    FCS,
    ExtendedFlowSpecification,
    ExtendedWindowSize,
}

impl ConfigOptionData {
    fn new(data: &[u8]) -> Self {
        let opt_type = data[0];
        let data = &data[2..];
        match opt_type {
            0x01 => ConfigOptionData::MTU(ConfigOptionMTU::new(data)),
            0x02 => ConfigOptionData::FlushTimeout,
            0x03 => ConfigOptionData::QOS,
            0x04 => ConfigOptionData::RetransmissionAndFlowControl,
            0x05 => ConfigOptionData::FCS,
            0x06 => ConfigOptionData::ExtendedFlowSpecification,
            0x07 => ConfigOptionData::ExtendedWindowSize,
            _ => ConfigOptionData::Undefined,
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        match self {
            ConfigOptionData::MTU(option) => option.as_json(start_byte),
            _ => "".to_string(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct ConfigOption {
    opt_type: u8,
    opt_len: u8,
    data: ConfigOptionData,
}

impl ConfigOption {
    fn new(data: &[u8]) -> Self {
        let opt_type = data[0];
        let opt_len = data[1];

        let data = ConfigOptionData::new(data);
        ConfigOption {
            opt_type,
            opt_len,
            data,
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let opt_type_s =
            ParseBytesNode::new(start_byte, 1).format("Option Type", self.opt_type, "", "");
        let opt_len_s =
            ParseBytesNode::new(start_byte + 1, 1).format("Option Length", self.opt_len, "", "");
        let data_s = self.data.as_json(start_byte + 2);

        format!(
            r#""Configuration Options": {{{}, {}, {}}}"#,
            opt_type_s, opt_len_s, data_s
        )
    }
}

#[derive(Debug, PartialEq)]
struct ConfigOptionMTU {
    mtu: u16,
}

impl ConfigOptionMTU {
    fn new(data: &[u8]) -> Self {
        ConfigOptionMTU {
            mtu: u16::from_le_bytes([data[0], data[1]]),
        }
    }

    fn as_json(&self, start_byte: u8) -> String {
        let mtu_s = ParseBytesNode::new(start_byte, 2).format("MTU", self.mtu, "", "");

        format!("{}", mtu_s)
    }
}

#[derive(Debug, PartialEq)]
enum PSM {
    Undefined,
    SDP,
    RFCOMM,
    TCSBin,
    TCSBinCordless,
    BNEP,
    HIDControl,
    HIDInterrupt,
    UPnP,
    AVCTP,
    AVDTP,
    AVCTPBrowsing,
    UDICPlane,
    ATT,
    ThreeDSP,
    LEPsmIpsp,
    OTS,
    EATT,
}

impl Default for PSM {
    fn default() -> Self {
        PSM::Undefined
    }
}

impl PSM {
    fn new(_data: &[u8], psm: u16) -> Self {
        match psm {
            0x0001 => PSM::SDP,
            0x0003 => PSM::RFCOMM,
            0x0005 => PSM::TCSBin,
            0x0007 => PSM::TCSBinCordless,
            0x000F => PSM::BNEP,
            0x0011 => PSM::HIDControl,
            0x0013 => PSM::HIDInterrupt,
            0x0015 => PSM::UPnP,
            0x0017 => PSM::AVCTP,
            0x0019 => PSM::AVDTP,
            0x001B => PSM::AVCTPBrowsing,
            0x001D => PSM::UDICPlane,
            0x001F => PSM::ATT,
            0x0021 => PSM::ThreeDSP,
            0x0023 => PSM::LEPsmIpsp,
            0x0025 => PSM::OTS,
            0x0027 => PSM::EATT,
            _ => PSM::Undefined,
        }
    }

    fn fake_new(psm: u16) -> Self {
        let data = vec![0; 255];
        PSM::new(&data, psm)
    }

    fn get_name(&self) -> String {
        let name = match self {
            PSM::SDP => "SDP",
            PSM::RFCOMM => "RFCOMM",
            PSM::TCSBin => "TCS-BIN",
            PSM::TCSBinCordless => "TCS-BIN-CORDLESS",
            PSM::BNEP => "BNEP",
            PSM::HIDControl => "HID-Control",
            PSM::HIDInterrupt => "HID-Interrupt",
            PSM::UPnP => "UPnP",
            PSM::AVCTP => "AVCTP",
            PSM::AVDTP => "AVDTP",
            PSM::AVCTPBrowsing => "AVCTP-Browsing",
            PSM::UDICPlane => "UDIC-Plane",
            PSM::ATT => "ATT",
            PSM::ThreeDSP => "3DSP",
            PSM::LEPsmIpsp => "LE-PSM-IPSP",
            PSM::OTS => "OTS",
            PSM::EATT => "EATT",
            PSM::Undefined => "Undefined",
        };
        name.to_string()
    }

    #[allow(unused)]
    fn get_value(&self) -> u16 {
        match self {
            PSM::SDP => 0x0001,
            PSM::RFCOMM => 0x0003,
            PSM::TCSBin => 0x0005,
            PSM::TCSBinCordless => 0x0007,
            PSM::BNEP => 0x000F,
            PSM::HIDControl => 0x0011,
            PSM::HIDInterrupt => 0x0013,
            PSM::UPnP => 0x0015,
            PSM::AVCTP => 0x0017,
            PSM::AVDTP => 0x0019,
            PSM::AVCTPBrowsing => 0x001B,
            PSM::UDICPlane => 0x001D,
            PSM::ATT => 0x001F,
            PSM::ThreeDSP => 0x0021,
            PSM::LEPsmIpsp => 0x0023,
            PSM::OTS => 0x0025,
            PSM::EATT => 0x0027,
            PSM::Undefined => panic!("psm undefined!"),
        }
    }
}
