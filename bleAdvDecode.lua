-- 创建一个新的 dissector，确保描述唯一
local p_btle_adv = Proto("BTLE_ADV", "My Bluetooth LE Advertising")

-- 定义字段
local f_access_address = ProtoField.uint32("btle_adv.access_address", "Access Address", base.HEX)
local f_packet_header = ProtoField.uint16("btle_adv.packet_header", "Packet Header", base.HEX)
local f_advertising_address = ProtoField.ether("btle_adv.advertising_address", "Advertising Address")
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

    -- 解析 Advertising Address (第24-29字节，倒序解析)
    local advertising_address = buffer(23, 6):ether() -- 以太网格式解析
    subtree:add(f_advertising_address, buffer(23, 6), advertising_address)

    -- 解析剩余部分为 Payload
    local payload = buffer(29, buffer:len() - 29)
    local payload_tree = subtree:add(f_payload, payload, "Payload Data")

    -- 解析 Location Info (第43-50字节)
    local x_location = buffer(42, 4):uint() -- 解析 X 位置信息
    local y_location = buffer(46, 4):uint() -- 解析 Y 位置信息
    payload_tree:add(f_location_x, buffer(42, 4), x_location)
    payload_tree:add(f_location_y, buffer(46, 4), y_location)

    -- 更新 Info 栏，显示位置信息
    pinfo.cols.info = string.format("X: %d, Y: %d", x_location, y_location)
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