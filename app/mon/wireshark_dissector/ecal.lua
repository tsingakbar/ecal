-- 1. wireshark - perference - Protocols - Protobuf - Protobuf search paths:
--    configure this to make sure wireshark loads ecal's proto files
-- 2. About wireshark - folders - Personal Lua Plugins:
--    place this lua plugin to this folder so wireshark can load it.


ecal_udp_sample_protocol = Proto("EcalUdpSample",  "Ecal UDP Sample Protocol")

field_header_mark = ProtoField.string("header.ECAL")
field_header_version = ProtoField.uint32("header.version")
field_header_type = ProtoField.uint32("header.type")
field_header_id = ProtoField.int32("header.id")
field_header_num = ProtoField.uint32("header.num")
field_header_length = ProtoField.uint32("header.body_length")
field_sample_name_length = ProtoField.uint16("sample.name_length")
field_sample_name = ProtoField.string("sample.name")

ecal_udp_sample_protocol.fields = {
  field_header_mark,
  field_header_version,
  field_header_type,
  field_header_id,
  field_header_num,
  field_header_length,
  field_sample_name_length,
  field_sample_name,
}

local protobuf_dissector = Dissector.get("protobuf")
local identify_port = 14000

function ecal_udp_sample_protocol.dissector(buffer, pinfo, tree)
  -- only match destination port
  if pinfo.dst_port ~= identify_port then return end
  if buffer:len() == 0 then return end

  pinfo.cols.protocol = ecal_udp_sample_protocol.name

  local subtree = tree:add(ecal_udp_sample_protocol, buffer(), "Ecal UDP Sample Data")
  subtree:add_le(field_header_mark, buffer(0, 4))
  subtree:add_le(field_header_version, buffer(4, 4))
  subtree:add_le(field_header_type, buffer(8, 4))
  subtree:add_le(field_header_id, buffer(12, 4))
  subtree:add_le(field_header_num, buffer(16, 4))
  subtree:add_le(field_header_length, buffer(20, 4))
  subtree:add_le(field_sample_name_length, buffer(24, 2))
  local sample_name_length = buffer(24, 2):le_uint()
  subtree:add_le(field_sample_name, buffer(26, sample_name_length))

  pinfo.private["pb_msg_type"] = "message,eCAL.pb.Sample"
  pcall(Dissector.call, protobuf_dissector, buffer(26+sample_name_length):tvb(), pinfo, tree)
end

DissectorTable.get("udp.port"):add(identify_port, ecal_udp_sample_protocol)