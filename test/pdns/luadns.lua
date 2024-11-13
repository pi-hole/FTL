refused_ede15 = newDN("refused.ede15.ftl")
nxdomain_ede15 = newDN("nxdomain.ede15.ftl")
null_ede15 = newDN("null.ede15.ftl")


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

        -- as we do not set dq.variable, our decision here will be cached

        return false
end
