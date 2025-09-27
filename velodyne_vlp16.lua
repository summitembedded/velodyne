-- Velodyne VLP-16 Dissector for Wireshark (No Header, No Block Status)
-- Supports UDP port 2372, payload starts with data blocks (0xFFEE BE at offset 0)
-- Parses up to 12 data blocks (100 bytes each: ID BE + azimuth BE + 32 lasers (3 bytes each: dist LE + int))
-- Handles shorter payloads (your 1206 bytes)

local velodyne_vlp16 = Proto("velodyne_vlp16", "Velodyne VLP-16 Packet")

-- Block fields
local f_block_id = ProtoField.uint16("velodyne.block_id", "Block ID (0xFFEE BE)")
local f_azimuth = ProtoField.float("velodyne.azimuth", "Azimuth Angle (deg, BE)")
local f_distance = ProtoField.float("velodyne.distance", "Distance (m, LE)")
local f_intensity = ProtoField.float("velodyne.intensity", "Intensity (0-1)")
local f_laser_id = ProtoField.uint8("velodyne.laser_id", "Laser ID (0-15)")

-- Footer
local f_footer = ProtoField.bytes("velodyne.footer", "Footer (6 bytes)")

velodyne_vlp16.fields = { f_block_id, f_azimuth, f_distance, f_intensity, f_laser_id, f_footer }

-- Dissector function
function velodyne_vlp16.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 100 then  -- Minimum for one block
        return
    end

    pinfo.cols.protocol = velodyne_vlp16.name
    local subtree = tree:add(velodyne_vlp16, buffer(), "Velodyne VLP-16 Data (Length: " .. length .. ")")

    -- Data blocks (start at offset 0, 100 bytes each)
    local valid_points = 0
    local max_blocks = math.min(12, math.floor(length / 100))
    for block = 0, max_blocks - 1 do
        local block_start = block * 100
        if block_start + 100 > length then
            break
        end

        -- Block ID (bytes 0-1 of block, uint16 BE)
        local block_id_raw = buffer(block_start, 2):uint(1)  -- Big-endian
        if block_id_raw ~= 0xFFEE then
            subtree:append_text(", Invalid block ID at block " .. (block + 1) .. " (expected 0xFFEE, got 0x" .. string.format("%04X", block_id_raw) .. ")")
            break
        end

        local block_tree = subtree:add(tree, buffer(block_start, 100), "Data Block " .. (block + 1) .. " (ID: 0xFFEE)")

        -- Azimuth (bytes 2-3, uint16 BE / 100)
        local azimuth_raw = buffer(block_start + 2, 2):uint(1)  -- Big-endian
        local azimuth_deg = azimuth_raw / 100.0
        block_tree:add(f_azimuth, buffer(block_start + 2, 2), azimuth_deg)

        -- 32 laser returns (bytes 4-99, 3 bytes each: dist uint16 LE, int uint8)
        for laser = 0, 31 do
            local laser_id = laser % 16
            local laser_start = block_start + 4 + laser * 3
            if laser_start + 3 > block_start + 100 then
                break
            end
            local dist_raw = buffer(laser_start, 2):uint(0)  -- Little-endian
            local dist_m = dist_raw * 0.002  -- Scale to meters
            local intensity_raw = buffer(laser_start + 2, 1):uint()
            local intensity_norm = intensity_raw / 255.0

            -- Add laser subtree
            local laser_tree = block_tree:add(tree, buffer(laser_start, 3), "Laser " .. laser_id .. " (Seq " .. (math.floor(laser / 16) + 1) .. ")")
            laser_tree:add(f_laser_id, buffer(laser_start, 1), laser_id)
            laser_tree:add(f_distance, buffer(laser_start, 2), dist_m)
            laser_tree:add(f_intensity, buffer(laser_start + 2, 1), intensity_norm)

            -- Count valid points (0.4-120m, intensity > 0.1)
            if dist_m >= 0.4 and dist_m <= 120.0 and intensity_norm > 0.1 then
                valid_points = valid_points + 1
            end
        end
    end

    -- Footer (last 6 bytes, if length >= 1200)
    if length >= 1200 then
        local footer_start = length - 6
        subtree:add(f_footer, buffer(footer_start, 6))
    end

    -- Summary in info column
    pinfo.cols.info = "Valid points: " .. valid_points .. "/" .. (max_blocks * 32) .. " (0.4-120m, intensity >0.1)"
end

-- Register for UDP port 2372
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(2372, velodyne_vlp16)