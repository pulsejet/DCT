#ifndef DCTMODEL_HPP
#define DCTMODEL_HPP
/*
 * Data Centric Transport schema policy model abstraction
 *
 * Copyright (C) 2020 Pollere, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <algorithm>
#include <functional>
#include <string_view>
#include <set>
#include <unordered_map>
#include <utility>
#include "buildpub.hpp"
#include "certstore.hpp"
#include "dct/format.hpp"
#include "dct/utility.hpp"
#include "validate_bootstrap.hpp"
#include "validate_pub.hpp"
#include "dct/distributors/dist_cert.hpp"
#include "dct/distributors/dist_gkey.hpp"


using Publication = ndn_ind::Data;

//template<typename sPub>
struct DCTmodel {
    certStore cs_{};        // certificates used by this model instance
    std::unordered_multimap<thumbPrint,dctCert> pending_{};
    const bSchema& bs_;     // trust schema for this model instance
    pubBldr<false> bld_;    // publication builder/verifier
    SigMgrAny psm_;         // publication signing/validation
    SigMgrAny wsm_;         // wire packet signing/validation
    SigMgrSchema syncSm_;   // syncps pub validator
    syncps::SyncPubsub m_sync;  // sync collection for pubs
    static inline std::function<size_t(std::string_view)> _s2i;
    DistCert m_ckd;         // cert collection distributor
    DistGKey* m_gkd{};      // group key distributor (if needed)
    tpToValidator pv_{};    // map signer thumbprint to pub structural validator

    SigMgr& wireSigMgr() { return wsm_.ref(); }
    SigMgr& pubSigMgr() { return psm_.ref(); }
    auto pubPrefix() const { return bs_.pubVal("#pubPrefix"); }
    auto wirePrefix() const { return bs_.pubVal("#wirePrefix"); }

    const auto& certs() const { return cs_; }

    bool isSigningCert(const dctCert& cert) const {
        // signing certs are the first item each signing chain so go through
        // all the chains and see if the first item matches 'cert'
        for (const auto& chn : bs_.chain_) {
            if (chn.size() == 0) continue;
            if (matches(bs_, cert.getName(), bs_.cert_[chn[0]])) return true;
        }
        return false;
    }

    // setup the information needed to validate pubs signed with the cert
    // associated with 'tp' which is the head of schema signing chain 'chain'.
    void setupPubValidator(const thumbPrint& tp) {
        //XXX this is a hack and should be refactored
        // Make a temporary builder to construct the pub templates associated
        // with this signing chain. To do this we need a *copy* of the current
        // certstore with its signing chain 0 set to 'tp'.
        certStore cs = cs_;
        cs.chains_[0] = tp;
        pubBldr bld(bs_, cs, bs_.pubName(0));
        pv_.emplace(tp, pubValidator(std::move(bld.pt_), std::move(bld.ptm_),
                                     std::move(bld.ptok_), std::move(bld.pstab_)));
    }

    // Check if newly added cert 'tp' allows validation of pending cert(s)
    // Validating and adding a pending cert may allow others to be validated
    // so this routine can get called recursively but the recursion depth
    // should be at most the schema's max signing chain length - 2.
    void checkPendingCerts(const dctCert& cert, const thumbPrint& tp) {
        auto [b, e] = pending_.equal_range(tp);
        if (b == e) return;
        for (auto i = b; i != e; ++i) {
            auto& p = i->second;
            if (pubSigMgr().validate(p, cert)) addCert(p);
        }
        pending_.erase(tp);
    }

    // Cryptographically and structurally validate a cert before adding it to the
    // cert store. Since certs can arrive in any order, a small number of certs
    // are held pending their signing cert's arrival.
    void addCert(const dctCert& cert) {
        const auto tp = cert.computeThumbPrint();
        if (cs_.contains(tp)) return;
        // check if cert is consistent with the schema
        try {
            auto ctype = cert.getSigType();
            if (ctype != pubSigMgr().type()) return; // signature doesn't match schema

            const auto& cname = cert.getName();
            if (matchesAny(bs_, cname) < 0) return; // name doesn't match schema

            // new root certs and schemas arriving in a session generally
            // result from a configuration error (e.g., updating a schema in
            // some but not all id bundles) so ignore them.
            // XXX eventually need tools to securely check/update certs & bundles
            const auto& stp = cert.getKeyLoc();
            if (dctCert::selfSigned(stp)) {
                //_LOG_WARNING("ignoring new root cert " << cname);
                return;
            }
            if (cname.size() >= 8 && to_sv(cname[-6]) == "schema") {
                //_LOG_WARNING("ignoring new schema cert " << cname);
                return;
            }

            // cert is structurally ok so see if it crytographically validates
            if (! cs_.contains(stp)) {
                // don't have cert's signing cert - check it when that arrives
                if (pending_.size() > 32) {
                    // XXX too many pending certs - drop something
                } 
                pending_.emplace(stp, cert);
                return;
            }
            if (! pubSigMgr().validate(cert, cs_[stp])) return;

            if (isSigningCert(cert)) {
                // we validated a signing cert which means we have its entire chain
                // in the certstore so we can validate all the names in the chain
                // against the schema. If the chain is ok, set up structural validation
                // state for pubs signed with this thumbprint.
                auto chain = validateChain(bs_, cs_, cert);
                if (chain < 0) return; // chain structurally invalid
                cs_.add(cert);
                setupPubValidator(tp);
                return; // done since nothing can be pending on a signing cert
            }
            cs_.add(cert);
        } catch (const std::exception&) {};
        checkPendingCerts(cert, tp);
    }


    // create a new DCTmodel instance using the certs in the bootstrap bundle file 'bootstrap'
    DCTmodel(std::string_view bootstrap) :
            bs_{validateBootstrap(bootstrap, cs_)},
            bld_{pubBldr(bs_, cs_, bs_.pubName(0))},
            psm_{getSigMgr(bs_)},
            wsm_{getWireSigMgr(bs_)},
            syncSm_{psm_.ref(), bs_, pv_},
            m_sync{syncps::SyncPubsub(wirePrefix() + "/pub", wireSigMgr(), syncSm_)},
            m_ckd{ bs_.pubVal("#pubPrefix"), bs_.pubVal("#wirePrefix") + "/cert",
                   [this](auto cert){ addCert(cert);},  [](auto /*p*/){return false;} }
    {
        if(wsm_.ref().type() == SigMgr::stAEAD) {
            m_gkd = new DistGKey(pubPrefix(), wirePrefix() + "/key",
                             [this](auto& gk, auto gkt){ wsm_.ref().addKey(gk, gkt);}, certs());
        }
        // cert distributor needs a callback when cert added to certstore.
        // when it's set up, push all the certs that went in prior to the
        // callback to the distributor (all the bootstrap info).
        // If using AEAD wireSigMgr, the group key distributor needs an update for new members
        //  (but shouldn't call with its own signing key)
        if (m_gkd) {
            cs_.addCb_ = [this, &ckd=m_ckd, &gkd=*m_gkd] (const dctCert& cert) {
                            ckd.publishCert(cert);
                            if (isSigningCert(cert)) gkd.addGroupMem(cert);
                         };
        } else {
            cs_.addCb_ = [&ckd=m_ckd] (const dctCert& cert) { ckd.publishCert(cert); };
        }
        for (const auto& [tp, cert] : cs_) m_ckd.initialPub(dctCert(cert));

        // pub and wire sigmgrs each need its signing key setup and its validator needs
        // a callback to return a public key given a cert thumbprint.
        const auto& tp = cs_.Chains()[0]; // thumbprint of signing cert
        pubSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
        wireSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
        pubSigMgr().setKeyCb([&cs=cs_](const ndn_ind::Data& d) -> const keyVal& { return *(cs[d].getContent()); });
        wireSigMgr().setKeyCb([&cs=cs_](const ndn_ind::Data& d) -> const keyVal& { return *(cs[d].getContent()); });


        // SPub need access to builder's 'index' function to translate component names to indices
        _s2i = std::bind(&decltype(bld_)::index, bld_, std::placeholders::_1);
    }

    // export the syncps API
 
    auto run() { m_sync.run(); };

    auto& subscribeTo(const syncps::Name& topic, syncps::UpdateCb&& cb) {
        m_sync.subscribeTo(topic, std::move(cb));
        return *this;
    }
    auto& unsubscribe(const syncps::Name& topic) {
        m_sync.unsubscribe(topic);
        return *this;
    }
    auto publish(syncps::Publication&& pub) { return m_sync.publish(std::move(pub)); }

    auto publish(syncps::Publication&& pub, syncps::PublishCb&& cb) {
        return m_sync.publish(std::move(pub), std::move(cb));
    }

    auto& setSyncInterestLifetime(std::chrono::milliseconds t) {
        m_sync.syncInterestLifetime(t);
        return *this;
    }
    auto schedule(std::chrono::nanoseconds after, const std::function<void()>& cb) {
        return m_sync.schedule(after, cb);
    }

    // construct a pub name
    template<typename... Rest>
    auto name(Rest&&... rest) { return bld_.name(std::forward<Rest>(rest)...); }

    // construct a publication with the given content using rest of args to construct its name
    template<typename... Rest>
    auto pub(std::span<const uint8_t> content, Rest&&... rest) {
        Publication pub(name(std::forward<Rest>(rest)...));
        pubSigMgr().sign(pub.setContent(content.data(), content.size()));
        return pub;
    }

    // set defaults to be used when constructing pub names
    template<typename... Rest>
    auto defaults(Rest&&... rest) { return bld_.defaults(std::forward<Rest>(rest)...); }

    // set start callback for shims that have a separate connect/start like mbps
    void start(connectedCb&& cb, const std::function<bool()>&& kmcb =[](){return true;}) {
        if(! m_gkd) {
            // hook app start callback to cert distributor is 'connected' event
            m_ckd.setup(std::move(cb));
        } else {
            // 2nd argument to gkd.setup is whether this instance can be a keymaker.
            // (note: this will be settable via trust schema in future)
            m_ckd.setup(
                [&gkd=*m_gkd, cb=std::move(cb), km=kmcb()](bool connected) {
                    if (!connected) cb(false); else gkd.setup(cb, km);
                });
        }
    }

    struct sPub : Publication {
        using Publication::Publication;
        sPub(const Publication& p) { *this = reinterpret_cast<const sPub&>(p); }
        sPub(Publication&& p) { *this = std::move(reinterpret_cast<sPub&&>(p)); }

        // accessors for name components of different types

        size_t index(size_t s) const { return s;  }
        size_t index(std::string_view s) const { return _s2i(s); }

        std::string string(auto c) const { return getName()[index(c)].getValue().toRawStr(); }

        uint64_t number(auto c) const { return getName()[index(c)].toNumber(); }
        using ticks = std::chrono::microseconds; // period used in NDN timestamps
        using clock = std::chrono::sys_time<ticks>;
        clock time(auto c) const { return clock(ticks(getName()[index(c)].toTimestampMicroseconds())); }
        double timeDelta(auto c, std::chrono::system_clock::time_point tp = std::chrono::system_clock::now()) const {
                    return std::chrono::duration_cast<std::chrono::duration<double>>(tp - time(c)).count();
        }
        auto operator[](auto c) const { return string(c); }
    };
};

#endif // DCTMODEL_HPP
