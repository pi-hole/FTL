refused_ede15 = newDN("refused.ede15.ftl")
nxdomain_ede15 = newDN("nxdomain.ede15.ftl")
null_ede15 = newDN("null.ede15.ftl")
slow_blocked = newDN("slow-blocked.ftl")


-- this hook is called before doing any resolving
function preresolve(dq)
        pdnslog("Got question for "..dq.qname:toString().." from "..dq.remoteaddr:toString().." to "..dq.localaddr:toString())

        if dq.qname == refused_ede15 then
                pdnslog("Blocking REFUSED + EDE 15 for "..dq.qname:toString())
                -- Set EDE 15 in response
                dq.extendedErrorCode = 15
                -- Set REFUSED in response
                dq.rcode = pdns.REFUSED
                return true
        end

        if dq.qname == nxdomain_ede15 then
                pdnslog("Blocking NXDOMAIN + EDE 15 for "..dq.qname:toString())
                -- Set EDE 15 in response
                dq.extendedErrorCode = 15
                -- Set NXDOMAIN in response
                dq.rcode = pdns.NXDOMAIN
                return true
        end

        if dq.qname == null_ede15 then
                pdnslog("Blocking NULL + EDE 15 for "..dq.qname:toString())
                -- Set EDE 15 in response
                dq.extendedErrorCode = 15
                -- Add a NULL RR to the response
                dq:addAnswer(pdns.A, "0.0.0.0")
                dq:addAnswer(pdns.AAAA, "::")
                return true
        end

        if dq.qname:isPartOf(slow_blocked) then
                pdnslog("Holding back a large answer with a blocking address for "..dq.qname:toString())
                -- Hold the answer back for half a second so an identical
                -- query arriving meanwhile is attached to this one
                local start = os.clock()
                while os.clock() - start < 0.5 do end
                -- Too large for a requestor without EDNS(0): 41 A records
                dq:addAnswer(pdns.A, "146.112.61.104")
                for i = 1, 40 do
                        dq:addAnswer(pdns.A, "10.0.0."..i)
                end
                -- Do not answer the next query from the packet cache
                dq.variable = true
                return true
        end

        -- as we do not set dq.variable, our decision here will be cached

        return false
end
