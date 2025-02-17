-- 创建一个新的 dissector，确保描述唯一
local p_btle_adv = Proto("BTLE_ADV", "My Bluetooth LE Advertising")

-- 定义字段
local f_access_address = ProtoField.uint32("btle_adv.access_address", "Access Address", base.HEX)
local f_packet_header = ProtoField.uint16("btle_adv.packet_header", "Packet Header", base.HEX)
local f_advertising_address = ProtoField.string("btle_adv.advertising_address", "Advertising Address")
local f_location_x = ProtoField.uint32("btle_adv.location_x", "X Location", base.DEC)
local f_location_y = ProtoField.uint32("btle_adv.location_y", "Y Location", base.DEC)
local f_payload = ProtoField.bytes("btle_adv.payload", "Payload")
local f_mid = ProtoField.uint8("btle_adv.mid", "Mid", base.DEC)
local f_coarse = ProtoField.uint8("btle_adv.coarse", "Coarse", base.DEC)
local f_packet_id = ProtoField.uint16("btle_adv.packet_id", "Packet ID", base.DEC)

-- 为 dissector 添加字段
p_btle_adv.fields = { 
    f_access_address, 
    f_packet_header, 
    f_advertising_address, 
    f_location_x, 
    f_location_y, 
    f_payload, 
    f_mid, 
    f_coarse, 
    f_packet_id 
}

-- dissector 函数
function p_btle_adv.dissector(buffer, pinfo, tree)
    -- 检查数据包长度是否足够
    if buffer:len() < 58 then
        return
    end

    -- 设置协议名
    pinfo.cols.protocol = "BTLE_ADV"

    -- 添加到主解析树
    local subtree = tree:add(p_btle_adv, buffer(), "Bluetooth LE Advertising Packet")

    -- 解析 Access Address (第18-21字节，倒序解析)
    local access_address = buffer(17, 4):le_uint() -- 小端序解码
    subtree:add(f_access_address, buffer(17, 4), string.format("0x%08x", access_address))

    -- 解析 Packet Header (第22-23字节，倒序解析)
    local packet_header = buffer(21, 2):le_uint() -- 小端序解码
    subtree:add(f_packet_header, buffer(21, 2), string.format("0x%04x", packet_header))

    -- 解析 Advertising Address (第24-29字节，正确顺序显示)
    if buffer:len() >= 29 then
        local advertising_address = string.format(
            "%02x:%02x:%02x:%02x:%02x:%02x",
            buffer(28, 1):uint(),
            buffer(27, 1):uint(),
            buffer(26, 1):uint(),
            buffer(25, 1):uint(),
            buffer(24, 1):uint(),
            buffer(23, 1):uint()
        )
        subtree:add(f_advertising_address, advertising_address):append_text(" (formatted)")
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Advertising Address")
    end

    -- 解析 Payload
    if buffer:len() > 29 then
        local payload = buffer(29, buffer:len() - 29)
        local payload_tree = subtree:add(f_payload, payload, "Payload Data")

        -- 解析 Location Info (第39-46字节)
        local x_location, y_location = nil, nil
        if buffer:len() >= 50 then
            x_location = buffer(38, 4):uint()
            y_location = buffer(42, 4):uint()
            payload_tree:add(f_location_x, buffer(38, 4), x_location)
            payload_tree:add(f_location_y, buffer(42, 4), y_location)
        else
            payload_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Location Info")
        end

        -- 解析 Mid 和 Coarse (第49-50字节)
        local mid, coarse = nil, nil
        if buffer:len() >= 50 then
            mid = buffer(48, 1):uint() -- 第49字节
            coarse = buffer(49, 1):uint() -- 第50字节
            subtree:add(f_mid, buffer(48, 1), mid)
            subtree:add(f_coarse, buffer(49, 1), coarse)
        else
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Mid and Coarse")
        end

        -- 解析 Packet ID (第57-58字节，按网络字节序)
        local packet_id = nil
        if buffer:len() >= 58 then
            packet_id = buffer(56, 2):uint() -- 按大端序解码
            subtree:add(f_packet_id, buffer(56, 2), packet_id)
        else
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Packet ID")
        end

        -- 更新 Info 栏，显示所有解析信息
        local info_text = ""
        if x_location and y_location then
            info_text = string.format("X: %d, Y: %d", x_location, y_location)
        end
        if mid and coarse then
            info_text = info_text .. string.format(", Mid: %d, Coarse: %d", mid, coarse)
        end
        if packet_id then
            info_text = info_text .. string.format(", ID: %d", packet_id)
        end
        pinfo.cols.info = info_text
    end
end

--------------------------------------------------------------------
-- 下面开始注册 dissector
--------------------------------------------------------------------

-- 获取蓝牙LE链路层（WTAP_ENCAP_BLUETOOTH_LE_LL）的 DissectorTable
local wtap_encap_table = DissectorTable.get("wtap_encap")

-- 注册到 Nordic BLE 封装类型 (186)
local BLUETOOTH_LE_LL = 186
wtap_encap_table:add(BLUETOOTH_LE_LL, p_btle_adv)

-- 脚本结束