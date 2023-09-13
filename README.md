# HCI_PARSER_RS

纯 rust 实现的蓝牙 hci 解析的工具，目前在开发中

## 目前的效果

输入 `[0x03, 0x0c, 0x00]` 可以得到下面的输出

```json
{"Opcode":"0xc03", "OCF":"0x3", "OGF":"0x3", "Command":"Reset", "Parameter_Total_Length":"0x0"}
```

## 目前的情况

hci 层的解析

- [x] 添加一个 hci cmd 的解析
- [ ] 添加一个 hci evt 的解析
- [x] 添加一个 hci acl 的解析

l2cap 层的解析

- [x] 添加一个 signal cmd 的解析
