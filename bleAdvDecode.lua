-- 创建一个新的 dissector，确保描述唯一
local p_btle_adv = Proto("BTLE_ADV", "My Bluetooth LE Advertising")

-- 定义字段
local f_address = ProtoField.ether("btle_adv.address", "Advertising Address")
local f_unknown_type = ProtoField.uint8("btle_adv.unknown_type", "Unknown Type", base.HEX)
local f_unknown_data = ProtoField.bytes("btle_adv.unknown_data", "Unknown Data")

-- 为 dissector 添加字段
p_btle_adv.fields = { f_address, f_unknown_type, f_unknown_data }

-- 广播地址常量
local target_address = "00:02:72:32:80:c6"

-- dissector 函数
function p_btle_adv.dissector(buffer, pinfo, tree)
    -- 检查数据包长度是否足够
    if buffer:len() < 6 then
        return
    end

    -- 获取广播地址（前 6 个字节）
    local address = tostring(buffer(0, 6):ether())

    -- 如果广播地址不匹配，则跳过
    if address ~= target_address then
        return
    end

    -- 设置协议名
    pinfo.cols.protocol = "BTLE_ADV"

    -- 更新 Info 列
    pinfo.cols.info = "BTLE ADV from " .. address

    -- 添加到主解析树
    local subtree = tree:add(p_btle_adv, buffer(), "Bluetooth LE Advertising Packet")
    subtree:add(f_address, buffer(0, 6))

    -- 找到 Unknown 数据（假设其类型为 0x4 且长度为 9）
    local offset = 6
    while offset < buffer:len() do
        local field_type = buffer(offset, 1):uint()
        local field_length = buffer(offset + 1, 1):uint()

        if field_type == 0x04 and field_length == 9 then
            local unknown_data = buffer(offset + 2, field_length)

            -- 将数据显示在 Info 列中
            pinfo.cols.info:append(" | Unknown Data: " .. tostring(unknown_data))

            -- 添加到树中
            local unknown_tree = subtree:add(buffer(offset, field_length + 2), "Unknown Field")
            unknown_tree:add(f_unknown_type, buffer(offset, 1))
            unknown_tree:add(f_unknown_data, unknown_data)
        end

        -- 跳到下一个字段
        offset = offset + field_length + 2
    end
end

--------------------------------------------------------------------
-- 下面开始注册 dissector
--------------------------------------------------------------------

-- 获取蓝牙LE链路层（WTAP_ENCAP_BLUETOOTH_LE_LL）的DissectorTable
-- 有时不同的 Wireshark 版本封装可能略有不同，如果注册地点不对，可以尝试其它表。
local wtap_encap_table = DissectorTable.get("wtap_encap")

-- WTAP_ENCAP_BLUETOOTH_LE_LL 一般是 251 (可以据 Wireshark 版本而异)
-- 也可以直接用枚举名称 wtap["WTAP_ENCAP_BLUETOOTH_LE_LL"] 来尝试
local BLUETOOTH_LE_LL = 154

-- 将我们的 mybleproto 加入到 BLE LL 的解析中
wtap_encap_table:add(BLUETOOTH_LE_LL, p_btle_adv)

-- 脚本结束