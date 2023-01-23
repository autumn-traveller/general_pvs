pvs_proto = Proto("pvs","Peer View Sampling")

local pvs_fields =  {
    version = ProtoField.uint8( "pvs.version", "Version", base.HEX, nil, 0xF0 ),
    msgtype = ProtoField.uint8( "pvs.msgtype", "Message Type", base.HEX, nil, 0x0F )
}

function parse_metadata(buffer, tree, ind)
    local start = ind
    local mtype = buffer(ind,1):uint()
    ind = ind + 1
    local encoded_len = buffer(ind,1):uint()
    ind = ind + 1
    local mlen = encoded_len
    if encoded_len > 247 then
        mlen = buffer(ind,encoded_len - 247):uint()
        ind = ind + encoded_len - 247
    end
    print("pvs: metadata length = " .. mlen)
    local tree = tree:add(buffer(start, mlen + ind - start), "Metadata")
    if mtype == 0 then
        tree:add(buffer(start,1), "Metadata type:", "Logical Timestamp")
        tree:add(buffer(start+1, ind - start - 1), "Metadata Length:", mlen)
        tree:add(buffer(ind, 4), "Logical Timestamp:", buffer(ind, 4):uint())
    elseif mtype == 1 then
        tree:add(buffer(start,1), "Metadata type:", "UTC Timestamp")
        tree:add(buffer(start+1, ind - start - 1), "Metadata Length:", mlen)
        tree:add(buffer(ind, 8), "UTC Timestamp:", os.date("%c", tonumber(buffer(ind, 8):int64())))
    else
        tree:add(buffer(start,1), "Metadata type:", "Other")
        tree:add(buffer(start+1,ind - start - 1),"Metadata Length:",mlen)
    end
    ind = ind + mlen
    print("pvs: metadata, read " .. ind - start  .. " bytes")
    return ind - start
end

local address_switch_case = {
	[0] = function (buffer,tree,ind,start)
        tree:add(buffer(start,1), "Address type:", "Reflexive")
        tree:add(buffer(start+1, ind - start - 1), "Address Length:", 0)
        -- TODO: take address from udp/tcp and ip
    end,

    [1] = function (buffer,tree,ind,start)
        tree:add(buffer(start,1), "Address type:", "IPv4")
        tree:add(buffer(start+1, ind - start - 1), "Address Length:", 4)
        tree:add(buffer(ind, 4), "IPv4 Address:", tostring(buffer(ind, 4):ipv4()))
    end,

    [2] = function (buffer,tree,ind,start)
        tree:add(buffer(start,1), "Address type:", "(IPv4, Port) Tupel")
        tree:add(buffer(start+1, ind - start - 1), "Address Length:", 6)
        tree:add(buffer(ind, 4), "IPv4 Address:", tostring(buffer(ind, 4):ipv4()))
        tree:add(buffer(ind+4, 2), "Port: ", buffer(ind+4, 2):uint())
    end,

    [3] = function (buffer,tree,ind,start)
        tree:add(buffer(start,1), "Address type:", "IPv6")
        tree:add(buffer(start+1, ind - start - 1), "Address Length:", 16)
        tree:add(buffer(ind, 16), "IPv6 Address:", tostring(buffer(ind, 16):ipv6()))
    end,

    [4] = function (buffer,tree,ind,start)
        tree:add(buffer(start,1), "Address type:", "(IPv6, Port) Tupel")
        tree:add(buffer(start+1, ind - start - 1), "Address Length:", 18)
        tree:add(buffer(ind, 16), "IPv6 Address:", tostring(buffer(ind, 16):ipv6()))
        tree:add(buffer(ind+16, 2), "Port: ", buffer(ind+16, 2):uint())
    end,
}

function parse_addr(buffer, tree, ind)
    local start = ind
    local addrtype = buffer(ind,1):uint()
    ind = ind + 1
    local encoded_len = buffer(ind,1):uint()
    ind = ind + 1
    local alen = encoded_len
    if encoded_len > 247 then
        alen = buffer(ind,encoded_len - 247):uint()
        ind = ind + encoded_len - 247
    end
    print("pvs: addr length = " .. alen)
    local tree = tree:add(buffer(start, alen + ind - start), "Address")

    local func = address_switch_case[addrtype]
    if func then
        func(buffer, tree, ind, start)
    else
        tree:add(buffer(start,1), "Address type:", "Unknown")
        tree:add(buffer(start+1,ind - start - 1),"Address Length:",alen)
    end
    ind = ind + alen
    print("pvs: address, read " .. ind - start  .. " bytes")
    return ind - start
end

function parse_peer(buffer, tree, ind)
    local start = ind
	local subtree = tree:add(buffer(ind,0),"Peer Entry")
    
    local numaddr = buffer(ind,1):uint()
    print("pvs: peer num addresses = " .. numaddr)
    subtree:add(buffer(ind,1), "Number of Addresses:",numaddr)
    ind = ind + 1

    local metalen = buffer(ind,1):uint()
    print("pvs: peer num metadata blocks = " .. metalen)
    subtree:add(buffer(ind,1), "Number of Metadata Blocks:",metalen)
    ind = ind + 1

    for i = 1, numaddr do
        ind = ind + parse_addr(buffer,subtree,ind)
    end
    for i = 1, metalen do
        ind = ind + parse_metadata(buffer,subtree,ind)
    end
    return ind - start
end

pvs_proto.fields = pvs_fields

-- the dissector function
function pvs_proto.dissector(buffer, pinfo, tree)
	local plen = buffer:captured_len()
	print("pvs dissector, captured buf len = " .. plen)
    if plen == 0 then
        return
    end
    pinfo.cols.protocol = "PVS"
    local subtree = tree:add(pvs_proto,buffer(),"Peer View Sampling Protocol")
    local b1 = buffer(0,1):uint()
    local bit = buffer(0,1):bitfield(6,1) 
    subtree:add(pvs_fields.version, buffer:range(0,1))
    subtree:add(pvs_fields.msgtype, buffer:range(0,1))
    subtree:add(buffer(1,1), "Magic:", buffer(1,1):uint())
    local viewsize = buffer(2,1):uint()
    local metasize = buffer(3,1):uint()
    subtree:add(buffer(2,1), "View Size:", viewsize)
    subtree:add(buffer(3,1), "Metadata Size:", metasize)
    
    local offset = 4 -- we have read 4 bytes up till now
    
    local viewtree = subtree:add(buffer(offset,0),"Peers in View")
    for i = 1, viewsize do
        offset = offset + parse_peer(buffer,viewtree,offset)
    end
    
    local metatree = subtree:add(buffer(offset,0),"Message Metadata")
    for i = 1, metasize do
        offset = offset + parse_metadata(buffer,metatree,offset)
    end
            

    return
end

-- register the dissector
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")
udp_table:add(7777,pvs_proto)
tcp_table:add(7777,pvs_proto)
