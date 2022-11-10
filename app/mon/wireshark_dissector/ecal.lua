-- 1. wireshark - perference - Protocols - Protobuf - Protobuf search paths:
--    configure this to make sure wireshark loads ecal's proto files
-- 2. About wireshark - folders - Personal Lua Plugins:
--    place this lua plugin to this folder so wireshark can load it.


ecal_udp_discovery_protocol = Proto("Ecal_Udp_Discovery",  "Ecal UDP Discovery Protocol")

discovery_field_header_mark = ProtoField.string("header.ECAL")
discovery_field_header_version = ProtoField.uint32("header.version")
discovery_field_header_type = ProtoField.uint32("header.type")
discovery_field_header_id = ProtoField.int32("header.id")
discovery_field_header_num = ProtoField.uint32("header.num")
discovery_field_header_length = ProtoField.uint32("header.body_length")
discovery_field_sample_name_length = ProtoField.uint16("sample.name_length")
discovery_field_sample_name = ProtoField.string("sample.name")

ecal_udp_discovery_protocol.fields = {
  discovery_field_header_mark,
  discovery_field_header_version,
  discovery_field_header_type,
  discovery_field_header_id,
  discovery_field_header_num,
  discovery_field_header_length,
  discovery_field_sample_name_length,
  discovery_field_sample_name,
}

local protobuf_dissector = Dissector.get("protobuf")
local discovery_port = 14000

function ecal_udp_discovery_protocol.dissector(buffer, pinfo, tree)
  -- only match destination port
  if pinfo.dst_port ~= discovery_port then return end
  if buffer:len() == 0 then return end

  pinfo.cols.protocol = ecal_udp_discovery_protocol.name

  local subtree = tree:add(ecal_udp_discovery_protocol, buffer(), "Ecal UDP Discovery Data")
  subtree:add_le(discovery_field_header_mark, buffer(0, 4))
  subtree:add_le(discovery_field_header_version, buffer(4, 4))
  subtree:add_le(discovery_field_header_type, buffer(8, 4))
  subtree:add_le(discovery_field_header_id, buffer(12, 4))
  subtree:add_le(discovery_field_header_num, buffer(16, 4))
  subtree:add_le(discovery_field_header_length, buffer(20, 4))
  subtree:add_le(discovery_field_sample_name_length, buffer(24, 2))
  local sample_name_length = buffer(24, 2):le_uint()
  subtree:add_le(discovery_field_sample_name, buffer(26, sample_name_length))

  pinfo.private["pb_msg_type"] = "message,eCAL.pb.Sample"
  pcall(Dissector.call, protobuf_dissector, buffer(26+sample_name_length):tvb(), pinfo, tree)
end

DissectorTable.get("udp.port"):add(discovery_port, ecal_udp_discovery_protocol)

------------------------------------------------------------------------------------

ecal_udp_message_protocol = Proto("Ecal_Udp_Message",  "Ecal UDP Message Protocol")

message_field_header_mark = ProtoField.string("header.ECAL")
message_field_header_version = ProtoField.uint32("header.version")
message_field_header_type = ProtoField.uint32("header.type")
message_field_header_id = ProtoField.int32("header.id")
message_field_header_num = ProtoField.uint32("header.num")
message_field_header_length = ProtoField.uint32("header.body_length")

ecal_udp_message_protocol.fields = {
  message_field_header_mark,
  message_field_header_version,
  message_field_header_type,
  message_field_header_id,
  message_field_header_num,
  message_field_header_length,
}

local message_port = 14002
function ecal_udp_message_protocol.dissector(buffer, pinfo, tree)
  -- only match destination port
  if pinfo.dst_port ~= message_port then return end
  if buffer:len() == 0 then return end

  pinfo.cols.protocol = ecal_udp_message_protocol.name

  local subtree = tree:add(ecal_udp_message_protocol, buffer(0, 24), "Ecal UDP Message Header")
  subtree:add_le(message_field_header_mark, buffer(0, 4))
  subtree:add_le(message_field_header_version, buffer(4, 4))
  subtree:add_le(message_field_header_type, buffer(8, 4))
  subtree:add_le(message_field_header_id, buffer(12, 4))
  subtree:add_le(message_field_header_num, buffer(16, 4))
  subtree:add_le(message_field_header_length, buffer(20, 4))
  local subtree_body = tree:add(ecal_udp_message_protocol, buffer(24), "Ecal UDP Message Body")
end

DissectorTable.get("udp.port"):add(message_port, ecal_udp_message_protocol)