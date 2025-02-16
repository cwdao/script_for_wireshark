-- 创建一个新的 dissector，确保描述唯一
local p_btle_adv = Proto("BTLE_ADV", "My Bluetooth LE Advertising")

-- 定义字段
local f_access_address = ProtoField.uint32("btle_adv.access_address", "Access Address", base.HEX)
local f_packet_header = ProtoField.uint16("btle_adv.packet_header", "Packet Header", base.HEX)
local f_advertising_address = ProtoField.string("btle_adv.advertising_address", "Advertising Address")
local f_location_x = ProtoField.uint32("btle_adv.location_x", "X Location", base.DEC)
local f_location_y = ProtoField.uint32("btle_adv.location_y", "Y Location", base.DEC)
local f_payload = ProtoField.bytes("btle_adv.payload", "Payload")

-- 为 dissector 添加字段
p_btle_adv.fields = { f_access_address, f_packet_header, f_advertising_address, f_location_x, f_location_y, f_payload }

-- dissector 函数
function p_btle_adv.dissector(buffer, pinfo, tree)
    -- 检查数据包长度是否足够
    if buffer:len() < 50 then
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
        -- 从 buffer 提取字节并以正确的顺序格式化
        local advertising_address = string.format(
            "%02x:%02x:%02x:%02x:%02x:%02x",
            buffer(28, 1):uint(), -- 第6字节
            buffer(27, 1):uint(), -- 第5字节
            buffer(26, 1):uint(), -- 第4字节
            buffer(25, 1):uint(), -- 第3字节
            buffer(24, 1):uint(), -- 第2字节
            buffer(23, 1):uint()  -- 第1字节
        )
        -- 添加到解析树中，值为手动格式化的地址
        subtree:add(f_advertising_address, advertising_address):append_text(" (formatted)")
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Advertising Address")
    end

    -- 解析剩余部分为 Payload
    if buffer:len() > 29 then
        local payload = buffer(29, buffer:len() - 29)
        local payload_tree = subtree:add(f_payload, payload, "Payload Data")

        -- 解析 Location Info (第39-46字节)
        if buffer:len() >= 50 then
            local x_location = buffer(38, 4):uint() -- 解析 X 位置信息
            local y_location = buffer(42, 4):uint() -- 解析 Y 位置信息
            payload_tree:add(f_location_x, buffer(38, 4), x_location)
            payload_tree:add(f_location_y, buffer(42, 4), y_location)

            -- 更新 Info 栏，显示位置信息
            pinfo.cols.info = string.format("X: %d, Y: %d", x_location, y_location)
        else
            payload_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Location Info")
        end
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