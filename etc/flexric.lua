-- Wireshark/tshark plugin: name the E2AP and E42 messages that FlexRIC
-- exchanges on its two SCTP ports.
--   36421  E2   gNB (E2 agent) <-> near-RT RIC
--   36422  E42  xApp           <-> near-RT RIC  (FlexRIC's own extension of E2AP)
local E2_PORT, E42_PORT = 36421, 36422

local flexric = Proto("flexric", "FlexRIC E2AP/E42")
local f_iface = ProtoField.string("flexric.interface", "Interface")
local f_pdu   = ProtoField.string("flexric.pdu", "PDU type")
local f_proc  = ProtoField.uint8("flexric.procedure_code", "Procedure code")
local f_msg   = ProtoField.string("flexric.message", "Message")
local f_slice = ProtoField.string("flexric.slice_quota", "Slice quota")
flexric.fields = { f_iface, f_pdu, f_proc, f_msg, f_slice }

-- First byte of an E2AP-PDU selects the PDU type.
local pdu_types = { [0x00] = "initiatingMessage", [0x20] = "successfulOutcome", [0x40] = "unsuccessfulOutcome" }

-- Procedure code -> message name for each PDU type.
local names = {
  [1]  = { "E2setupRequest", "E2setupResponse", "E2setupFailure" },
  [2]  = { "ErrorIndication" },
  [3]  = { "ResetRequest", "ResetResponse" },
  [4]  = { "RICcontrolRequest", "RICcontrolAcknowledge", "RICcontrolFailure" },
  [5]  = { "RICindication" },
  [6]  = { "RICserviceQuery" },
  [7]  = { "RICserviceUpdate", "RICserviceUpdateAcknowledge", "RICserviceUpdateFailure" },
  [8]  = { "RICsubscriptionRequest", "RICsubscriptionResponse", "RICsubscriptionFailure" },
  [9]  = { "RICsubscriptionDeleteRequest", "RICsubscriptionDeleteResponse", "RICsubscriptionDeleteFailure" },
  [10] = { "E2nodeConfigurationUpdate", "E2nodeConfigurationUpdateAcknowledge", "E2nodeConfigurationUpdateFailure" },
  [11] = { "E2connectionUpdate", "E2connectionUpdateAcknowledge", "E2connectionUpdateFailure" },
  [12] = { "RICsubscriptionDeleteRequired" },
  [13] = { "E2removalRequest", "E2removalResponse", "E2removalFailure" },
  -- E42: FlexRIC only
  [14] = { "E42setupRequest", "E42setupResponse" },
  [15] = { "E42RICsubscriptionRequest" },
  [16] = { "E42RICsubscriptionDeleteRequest" },
  [17] = { "E42RICcontrolRequest" },
}
local outcome_index = { [0x00] = 1, [0x20] = 2, [0x40] = 3 }

local e2ap = Dissector.get("e2ap")

-- Slice quotas in a control request from this lab's xApp. The xApp writes one
-- group of E2SM-RC RAN parameters per slice: SST (parameter 8), SD (parameter
-- 9) and the dedicated PRB ratio (parameter 12). Each is stored as
-- <ID - 1> <type> <length> <value>, so we look for that byte pattern instead
-- of decoding the whole E2SM-RC message.
local function slice_quotas(tvb)
  local hex = tostring(tvb:bytes()):lower()
  local found = {}
  for sst, sd, ratio in hex:gmatch("00072a0001(%x%x)00082a0001(%x%x)0009288001%x%x000a288001%x%x000b288001(%x%x)") do
    found[#found + 1] = string.format("SST %s / SD %s: dedicated PRB ratio %d%%",
      string.char(tonumber(sst, 16)), string.char(tonumber(sd, 16)), tonumber(ratio, 16))
  end
  return found
end

function flexric.dissector(tvb, pinfo, tree)
  if tvb:len() < 2 then return 0 end
  local pdu, proc = tvb(0, 1):uint(), tvb(1, 1):uint()
  local name = names[proc] and names[proc][outcome_index[pdu] or 0]
  if not name then return 0 end

  local iface, path
  if pinfo.dst_port == E2_PORT then iface, path = "E2", "gNB -> RIC"
  elseif pinfo.src_port == E2_PORT then iface, path = "E2", "RIC -> gNB"
  elseif pinfo.dst_port == E42_PORT then iface, path = "E42", "xApp -> RIC"
  else iface, path = "E42", "RIC -> xApp" end

  -- Standard E2AP messages: let the built-in dissector fill in the details.
  if proc <= 13 and e2ap then pcall(e2ap.call, e2ap, tvb, pinfo, tree) end

  local t = tree:add(flexric, tvb(), "FlexRIC " .. iface .. ": " .. name)
  t:add(f_iface, iface .. " (" .. path .. ")")
  t:add(f_pdu, tvb(0, 1), pdu_types[pdu])
  t:add(f_proc, tvb(1, 1))
  t:add(f_msg, name)
  local info = name .. "  [" .. path .. "]"
  if proc == 4 or proc == 17 then
    for _, q in ipairs(slice_quotas(tvb)) do
      t:add(f_slice, q)
      info = info .. "  " .. q:gsub(": dedicated PRB ratio", " ->")
    end
  end
  pinfo.cols.protocol = iface
  pinfo.cols.info = info
  return tvb:len()
end

local sctp_port = DissectorTable.get("sctp.port")
sctp_port:add(E2_PORT, flexric)
sctp_port:add(E42_PORT, flexric)
