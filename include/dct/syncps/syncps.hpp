#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP
#pragma once
/*
 * Copyright (C) 2019-2 Pollere LLC
 * Pollere authors at info@pollere.net
 *
 * This file is part of syncps (DCT pubsub via Collection Sync)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <ranges>
#include <type_traits>
#include <unordered_map>

#include <dct/face/direct.hpp>
#include <dct/format.hpp>
#include <dct/schema/dct_cert.hpp>
#include "iblt.hpp"

namespace dct {

// recognize containers that combine a view with its backing store
template<typename C> concept hasView = requires { std::remove_cvref_t<C>().asView(); };

using rPub = rData; // internal pub rep
using Name = rName; // type of a name
using Publication = crData;  // type of a publication

using namespace std::literals::chrono_literals;

//default values
static constexpr int maxPubSize = 1024; // max payload in Data (with 1448B MTU
                                        // and 424B iblt, 1K left for payload)
static constexpr std::chrono::milliseconds maxPubLifetime = 2s;
static constexpr std::chrono::milliseconds maxClockSkew = 1s;

static constexpr std::chrono::milliseconds distDelay = 50ms; // time for a PDU to be distributed to all members on this subnet
static constexpr std::chrono::milliseconds repubDelay = 50ms; // time to suppress republishing own publication

/**
 * @brief app callback when new publications arrive
 */
using SubCb = std::function<void(const rPub&)>;

/**
 * @brief callback when pub delivered or times out
 */
using DelivCb = std::function<void(const rPub&, bool)>;

/**
 * @brief app callback to test if publication is expired
 */
using IsExpiredCb = std::function<bool(const rPub&)>;
/**
 * @brief app callback to return lifetime of this Publication
 */
using GetLifetimeCb = std::function<std::chrono::milliseconds(const rPub&)>;
/**
 * @brief app callback to filter peer publication requests
 *
 * Changed the Cb to return a bool in order to indicate if new local pubs
 * are on the ordered vector. This value will be set to true in the default
 * so it has same behavior as before.
 */
using PubPtr = rPub;
using PubVec = std::vector<PubPtr>;
using OrderPubCb = std::function<bool(PubVec&,PubVec&)>;

/**
 * @brief sync a collection of publications between an arbitrary set of nodes.
 *
 * Application should call 'publish' to add a new publication to the
 * set and register an UpdateCallback that is called whenever new
 * publications from others are received. Publications are automatically
 * deleted (without notice) at the end their lifetime.
 *
 * Publications are named, signed objects (rData). The last component of
 * their name is a version number (local ms clock) that is used to bound the
 * pub lifetime. This component is added by 'publish' before the publication
 * is signed so it is protected against replay attacks. App publications
 * are signed by pubCertificate and external publications are verified by
 * pubValidator on arrival.
 */
struct SyncPS {
    using Error = std::runtime_error;
    using Nonce = uint32_t; // cState Nonce format

    // pubs are identified and accessed only by their hash. A pubs Collection entry holds the
    // actual pub Item, its source (local or from net) and whether it is active (unexpired).
    // The collection keeps both a hash-indexed map of entries and the iblt of the collection
    // so it can guarantee they are consistent with each other.
    using PubHash = uint32_t; // iblt publication hash type
    static inline PubHash hashPub(const rPub& r) { return IBLT<PubHash>::hashobj(r); }

    template<typename Item>
    struct CE { // Collection Entry 
        Item i_;
        uint8_t s_; // item status
        std::chrono::milliseconds sprs_{0ms};       // if non-zero, suppress until

        constexpr CE(Item&& i, uint8_t s) : i_{std::forward<Item>(i)}, s_{s} {}
        static constexpr uint8_t act = 1;  // 0 = expired, 1 = active
        static constexpr uint8_t loc = 2;  // 0 = from net, 2 = local
        auto active() const noexcept { return (s_ & act) != 0; }
        auto fromNet() const noexcept { return (s_ & (act|loc)) == act; }
        auto local() const noexcept { return (s_ & (act|loc)) == (act|loc); }
        auto& deactivate() { s_ &=~ act; return *this; }
    };

    template<typename Item, typename Ent = CE<Item>, typename Base = std::unordered_map<PubHash,Ent>>
    struct Collection : Base {
        IBLT<PubHash> iblt_{};

        constexpr auto& iblt() noexcept { return iblt_; }

        template<typename C=Item> requires hasView<C>
        constexpr auto contains(decltype(C().asView())&& c) const noexcept { return Base::contains(hashPub(c)); }

        PubHash add(PubHash h, Item&& i, decltype(Ent::s_) s) {
            if (const auto& [it,added] = Base::try_emplace(h, std::forward<Item>(i), s); !added) return 0;
            iblt_.insert(h);
            return h;
        }
        auto addLocal(PubHash h, Item&& i) { return add(h, std::forward<Item>(i), Ent::loc|Ent::act); }

        auto add(Item&& i, decltype(Ent::s_) s) { return add(hashPub(i), std::forward<Item>(i), s); }
        auto addLocal(Item&& i) { return add(std::forward<Item>(i), Ent::loc|Ent::act); }
        auto addNet(Item&& i) { return add(std::forward<Item>(i), Ent::act); }

        template<typename C=Item> requires hasView<C>
        auto addNet(decltype(C().asView())&& c) { return add(Item{c}, Ent::act); }

        auto deactivate(PubHash h) {
            if (auto p = Base::find(h); p != Base::end() && p->second.active()) {
                p->second.deactivate();
                iblt_.erase(h);
            }
        }
        auto erase(PubHash h) {
            if (auto p = Base::find(h); p != Base::end()) {
                if (p->second.active()) iblt_.erase(h);
                Base::erase(p);
            }
        }
    };

    Collection<crData> pubs_{};             // current publications
    Collection<DelivCb> pubCbs_{};          // pubs requesting delivery callbacks
    lpmLT<crPrefix,SubCb> subscriptions_{}; // subscription callbacks

    DirectFace& face_;
    const crName collName_;         // 'name' of the collection
    SigMgr& pktSigmgr_;             // cAdd packet signing and validation
    SigMgr& pubSigmgr_;             // Publication validation
    std::chrono::milliseconds cStateLifetime_{1357ms};
    std::chrono::milliseconds pubLifetime_{maxPubLifetime};
    std::chrono::milliseconds pubExpirationGB_{maxPubLifetime};
    pTimer scheduledCStateId_{std::make_shared<Timer>(getDefaultIoContext())};
    pTimer scheduledCAddId_{std::make_shared<Timer>(getDefaultIoContext())};
    std::uniform_int_distribution<unsigned short> randInt_{7u, 12u}; //  cState delay  randomization
    Nonce  nonce_{};                // nonce of current cState
    uint32_t publications_{};       // # locally originated publications
    bool delivering_{false};        // currently processing a cAdd
    bool registering_{true};        // RIT not set up yet
    bool autoStart_{true};          // call 'start()' when done registering
    GetLifetimeCb getLifetime_{ [this](auto){ return pubLifetime_; } };
    IsExpiredCb isExpired_{
        // default CB assumes last component of name is a timestamp and says pub is expired
        // if the time from publication to now is >= the pub lifetime
        [this](const auto& p) { auto dt = std::chrono::system_clock::now() - p.name().last().toTimestamp();
                         return dt >= getLifetime_(p) + maxClockSkew || dt <= -maxClockSkew; } };
    OrderPubCb orderPub_{[](PubVec& pv, PubVec&){   //default doesn't send others pubs
            // can't use modern c++ on a mac
            //std::ranges::sort(pOurs, {}, [](const auto& p) { return p.name().last().toTimestamp(); });
            std::sort(pv.begin(), pv.end(), [](const auto& p1, const auto& p2){
                    return p1.name().last().toTimestamp() > p2.name().last().toTimestamp(); });
            return true;    //to keep same behavior as before adding resending
        }
    };

    constexpr auto randInt() { return randInt_(randGen()); }

    /**
     * @brief constructor
     *
     * @param face - application's face
     * @param collName - collection name for cState/cAdd
     * @param wsig - sigmgr for cAdd packet signing and validation
     * @param psig - sigmgr for Publication validation
     */
    SyncPS(DirectFace& face, rName collName, SigMgr& wsig, SigMgr& psig)
        : face_{face}, collName_{collName}, pktSigmgr_{wsig}, pubSigmgr_{psig} {
        // if auto-starting at the time 'run()' is called, fire off a register for collection name
        getDefaultIoContext().dispatch([this]{ if (autoStart_) start(); });
    }

    SyncPS(rName collName, SigMgr& wsig, SigMgr& psig) : SyncPS(defaultFace(), collName, wsig, psig) {}


    /**
     * @brief add a new local or network publication to the 'active' pubs set
     */
    auto addToActive(crData&& p, bool localPub) {
        //print("addToActive {:x} {} {}: {}\n", hashPub(p), p.size(), p.name(), localPub);
        auto lt = getLifetime_(p);
        auto hash = localPub? pubs_.addLocal(std::move(p)) : pubs_.addNet(std::move(p));
        if (hash == 0 || lt == decltype(lt)::zero()) return hash;

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock skew).
        // An expired publication is never supplied in a cAdd so this hold time prevents
        // spurious end-of-lifetime exchanges due to clock skew.
        //
        // Expired publications are kept in the iblt for at least the max clock skew
        // interval to prevent a peer with a late clock giving it back to us as soon
        // as we delete it.

        if (localPub) oneTime(lt, [this, hash]{ if (pubCbs_.size() > 0) doDeliveryCb(hash, false); });
        oneTime(lt + maxClockSkew, [this, hash]{ pubs_.deactivate(hash); });
        oneTime(lt + pubExpirationGB_, [this, hash]{ pubs_.erase(hash); });
        return hash;
    }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and lives for at most pubLifetime.
     * Publications are signed before calling this routine.
     * Publications from the application always are additions to the collection so
     * are pushed to the network in response to any cState in PIT
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub) {
        auto h = addToActive(std::move(pub), true);
        if (h == 0) return h;
        ++publications_;
        // new pub is always sent if 1) not delivering 2) not registering and 3) a cState is in collection
        // If no cStates, send a cState including this pub at a short random delay
        if (!delivering_ && !registering_)   {   // don't send publications until completely registered for responses
            if (sendCAdd() == false) sendCStateSoon();
        }
        return h;
    }
    auto publish(const rData pub) { return publish(crData{pub}); }

    /**
     * @brief handle a new publication from app requiring a 'delivery callback'
     *
     * Takes a callback so pub arrival at other entity(s) can be confirmed or
     * failure reported so "at least once" semantics can be built into shim.
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub, DelivCb&& cb) {
        auto h = publish(std::move(pub));
        if (h != 0) pubCbs_.addLocal(h, std::move(cb));
        return h;
    }

    /**
     * @brief deliver a publication to a subscription's callback
     *
     * Since pub content may be encrypted, handles decrypting a copy
     * of the pub before presenting it to the subscriber then deleting
     * the copy (plaintext versions of encrypted objects must be ephemeral).
     */
    void deliver(const rPub& pub, const SubCb& cb) {
        if (pubSigmgr_.encryptsContent() && pub.content().size() > 0) {
            Publication pcpy{pub};
            if (pubSigmgr_.decrypt(pcpy)) cb(pcpy);
            return;
        }
        cb(pub);
    }

    /**
     * @brief subscribe to a topic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     */
    auto& subscribe(crPrefix&& topic, SubCb&& cb) {
        // print("syncps::subscribe called for {}\n", (rPrefix)topic);
        // add to subscription dispatch table. If subscription is new,
        // 'cb' will be called with each matching item in the active
        // publication list. Otherwise subscription will be
        // changed to the new callback.
        if (auto t = subscriptions_.find(topic); t != subscriptions_.end()) {
            t->second = std::move(cb);
            return *this;
        }
        // deliver all active pubs matching this subscription
        for (const auto& [h, pe] : pubs_) if (pe.fromNet() && topic.isPrefix(pe.i_.name())) deliver(pe.i_, cb);

        subscriptions_.add(std::move(topic), std::move(cb));
        return *this;
    }
    auto& subscribe(crName&& topic, SubCb&& cb) { return subscribe(crPrefix{std::move(topic)}, std::move(cb)); }
    auto& subscribe(const rName& topic, SubCb&& cb) { return subscribe(crPrefix{topic}, std::move(cb)); }

    auto& unsubscribe(crPrefix&& topic) { subscriptions_.erase(topic); return *this; }

    /**
     * @brief timers to schedule a callback after some time
     *
     * 'oneTime' schedules a non-cancelable callback, 'schedule' creates a cancelable/restartable
     * timer. Note that this is expensive compared to a oneTime timer and oneTime should be used
     * when the timer doesn't need to referenced.
     */
    auto schedule(std::chrono::microseconds after, TimerCb&& cb) const { return face_.schedule(after, std::move(cb)); }
    void oneTime(std::chrono::microseconds after, TimerCb&& cb) const { return face_.oneTime(after, std::move(cb)); }

    /**
     * @brief Send a cState describing our publication set to our peers.
     *
     * Creates & sends cState of the form: /<sync-prefix>/<own-IBF>
     * If called from interest timeout, set to to true
     */
    void sendCState() {
        // if a cState is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (registering_) return;

        scheduledCStateId_->cancel();
        nonce_ = rand32();
        face_.express(crInterest(collName_/pubs_.iblt().rlEncode(), cStateLifetime_, nonce_),
                        [this](auto& /*ri*/) { sendCState(); } // interest timeout for local cStates
                    );
    }

    /**
     * @brief Send a cState after a random delay. If called again before timer expires
     * restart the time. (This is used to collect all the cAdds responding to a cState
     * before sending a new cState.)
     */
    void sendCStateSoon(std::chrono::milliseconds dly = 0ms) {
        scheduledCStateId_->cancel();
        scheduledCStateId_ = schedule(dly + std::chrono::milliseconds(randInt()), [this]{ sendCState(); });
    }

    auto name2iblt(const rName& name) const noexcept {
        IBLT<PubHash> iblt{};
        try { iblt.rlDecode(name.last().rest()); } catch (const std::exception& e) { }
        return iblt;
    }

    void doDeliveryCb(PubHash hash, bool arrived) {
        auto cb = pubCbs_.find(hash);
        if (cb == pubCbs_.end()) return;

        // there's a callback for this hash. do it if pub was ours and is still active
        if (auto p = pubs_.find(hash); p != pubs_.end() && p->second.local()) (cb->second.i_)(p->second.i_, arrived);
        pubCbs_.erase(hash);
    }

    auto handleDeliveryCb(const auto& iblt) {
        if (pubCbs_.size()) {
            for (const auto hash : (pubs_.iblt() - pubCbs_.iblt() - iblt).peel().second) doDeliveryCb(hash, true);
        }
    }

    /**
     * @brief construct a cAdd appropriate for responding to cstate 'csName'
     *
     * The cAdd's name is the same as csName except the final component is replaced
     * with a murmurhash3 32 bit hash of csName which serves as both a compact
     * representation of csName's iblt and as a PIT key to retrieve the original
     * iblt should it be needed.
     */
    auto makeCAdd(const rName& csName) const noexcept {
        return crData{crName{csName.first(-1)}.append(tlv::Version, mhashView(csName)).done(),
                      tlv::ContentType_CAdd};
    }

    bool handleCState(const rName& name) {
        // The last component of 'name' is the peer's iblt. 'Peeling'
        // the difference between the peer's iblt & ours gives two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        //
        // pubCbs_ contains pubs that require delivery callbacks so which the peer already has.
        // pubs_ contains all pubs we have so send the ones we have & the peer doesn't.
        auto iblt{name2iblt(name)};
        handleDeliveryCb(iblt);
        auto [have, need] = (pubs_.iblt() - iblt).peel();
        if (need.size() == 0 && have.size() == 0 ) return false;    // handled cState same as current local cState

        // scheduledCStateId_->cancel();   // if a CState is scheduled, cancel it
        // scheduledCAddId_->cancel();     // if a scheduleCAddId_ is set, cancel it

        auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
        auto msNow =  now.time_since_epoch();
        PubVec pv{}, pvOth{};    //vectors of publications I have, local or others
        for (const auto hash : have) {
            //if (const auto& p = pubs_.find(hash); p != pubs_.end()) pv.emplace_back(p->second.i_);
            if (const auto& p = pubs_.find(hash); p != pubs_.end() ) {
                // on a broadcast channel pub suppression is give others time to receive these before resend
                if (p->second.sprs_ > msNow) continue;     // sent this pub too recently to send again
                p->second.sprs_ = 0ms;                     // set as unsuppressed
                if (p->second.local()) pv.emplace_back(p->second.i_);
                // else pvOth.emplace_back(p->second.i_);
            }
        }
        auto newPubs = false;
        if (!pv.empty() || !pvOth.empty()) newPubs = orderPub_(pv, pvOth);
        if (!newPubs) {
            if (need.size()) {
                // next cState should not be suppressed
                face_.unsuppressCState(rPrefix(collName_/pubs_.iblt().rlEncode()));
                sendCStateSoon(distDelay);
            }
            return false;
         }

        //auto othPubs = false;
        auto sprs = msNow + distDelay;   // only set suppression when pub is actually sent
        // send all the pubs that will fit in a cAdd packet, always sending at least one.
        assert(pv.size() > 0);
        for (size_t i{}, psize{}; i < pv.size(); ++i) {
            assert(pv[i].size() <= maxPubSize);
            if ((psize += pv[i].size()) > maxPubSize) {
                //if(pubs_.at(hashPub(pv[i])).fromNet()) othPubs = true;
                pv.resize(i);
                break;
            }
            pubs_.at(hashPub(pv[i])).sprs_ = sprs;
        }

        auto cAdd = makeCAdd(name).content(pv);
        // newPubs = true => there's a new local publication in this cAdd
        // othPubs =  true => there are publications from others in this cAdd
        if(newPubs && pv.size()) {   //both send and resend own with priority 
            if (pktSigmgr_.sign(cAdd)) face_.send(cAdd);
            // delay long enough for recipients to send cStates
            // (may be sooner if need.size() != 0 or not at all if these are not new)
            sendCStateSoon(2*distDelay);
        }
        return true;
    }

    /*
     * For publishing newly created, unsent publications
     * No need to go through previously received cStates, any cState will be missing new locally created Pubs
     * orderPubs puts newest first
     */
    bool sendCAdd(const rName name) {
        scheduledCStateId_->cancel();     // if a scheduleCStateId_ is set, cancel it
        //  scheduledCAddId_->cancel();     // if a scheduleCAddId_ is set, cancel it

        auto iblt{name2iblt(name)}; // use the retrieved cState's iblt to find new pubs
        // handleDeliveryCb(iblt); // this should have happened when the cstate first arrived
        auto [have, need] = (pubs_.iblt() - iblt).peel();
        if (have.size() == 0) return false;    // no new pubs

        auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
        auto msNow = now.time_since_epoch();
        PubVec pv{}, sv{};    // vectors of publications I have that were locally created, newest first
        for (const auto hash : have) {
            //if (const auto& p = pubs_.find(hash); p != pubs_.end()) pv.emplace_back(p->second.i_);
            if (const auto& p = pubs_.find(hash); p != pubs_.end() ) {
                // on a broadcast channel pub suppression is give others time to receive these before resend
                if (p->second.sprs_ > msNow) continue;     // sent this pub too recently to send again
                p->second.sprs_ = 0ms;                      // set as unsuppressed
                if (p->second.local()) pv.emplace_back(p->second.i_);
            }
        }
        if (pv.empty()) return false;
        if (! orderPub_(pv, sv)) return false;    //order priority returns all pubs to send in pv - puts new pubs first
        sv.clear();     // use for pubs to send

       auto sprs = msNow + distDelay;   // set suppression for pubs to be sent
        // send all the newPubs that will fit into a cAdd
        // skip over a pub that makes the cAdd oversize to see if any others will fit
        for (size_t i{}, sz{}; i < pv.size(); i++) {
             if (pv[i].size() > maxPubSize) {
                    print("sendCAdd: skipping {} which exceeds maxPubSize\n",pv[i].name());
                    continue;
                }
                if (sz + pv[i].size() > maxPubSize) continue;
                sz += pv[i].size();
                sv.emplace_back(pv[i]);
                pubs_.at(hashPub(pv[i])).sprs_ = sprs;
        }
        if (sv.empty()) return false;

        auto cAdd = makeCAdd(name).content(pv);
        if (! pktSigmgr_.sign(cAdd)) return false;
        face_.send(cAdd);
        // delay so receiving members can confirm.
        // if there are more new pubs to send, others' cStates will cause sending
        sendCStateSoon(2*distDelay);
        return true;
    }

    bool sendCAdd() {
        // look for a cState from network - would like to get most recent one from network
        const auto name  = face_.bestCState(collName_);
        if (name.size() == 0) return false;            // wait for a cState
        return sendCAdd(name);
    }

    /**
     * @brief Process cAdd after successful validation
     *
     * Add each item in cAdd content that we don't have to
     * our list of active publications then notify the
     * application about the updates.
     *
     * When onCAdd opportunistically processes *all* cAdds for this collection, should compare its iblt
     * against my current iblt with peel operation before pulling out content. I.e., if I "have"
     * everything in the iblt, don't process.
     *
     * Called for *any* cAdd in the collection, even if no matching cState in PIT
     * Can result in a change in local cState if any of the pubs are "needed"
     * A needed pub can also cause a local publication in response to delivering_
     * If no change in local cState, then the current cState shedule should not be change
     *
     * If there's a cState fromNet_, new pub will go out and a new cState should be scheduled soonish
     * If there's no cState fromNet_, a new cState should be scheduled soonish to let collection members know
     * "soonish" should be long enough to 1) collect other local cState changes 2) let other members process
     * the just-sent pub 3) un-suppress the just-sent pub in case it was missed
     * If keep getting cAdds, may keep pushing out the new cState
     * but what about a ready-to-send pub without a fromNet_ cState? Try NOT rescheduling cState (unless it is sent)
     *
     * @param cState   cState for which we got the cAdd
     * @param cAdd     cAdd content
     */
    void onCAdd(const rInterest& cState, const rData& cAdd) {
        if (registering_) return;   // don't process cAdds till fully registered

        // if publications result from handling this cAdd we don't want to
        // respond to a peer's cState until we've handled all of them.
        delivering_ = true;
        auto initpubs = publications_;

        auto ap = 0;    // added pubs from this cAdd
        for (auto c : cAdd.content()) {
            if (! c.isType(tlv::Data)) continue;
            rData d(c);
            if (! d.valid() || pubs_.contains(d)) {
                // print("syncps: pub invalid or dup: {}\n", d.name());
                continue;
            }
            if (isExpired_(d) || ! pubSigmgr_.validate(d)) {
                // print("pub {}: {}\n", isExpired_(d)? "expired":"failed validation", d.name());
                // unwanted pubs have to go in our iblt or we'll keep getting them
                ignorePub(d);
                continue;
            }

            // we don't already have this publication so add it to the
            // collection then deliver it to the longest match subscription.
            if (addToActive(crData(d), false) == 0) {
                // print("addToActive failed: {}\n", d.name());
                continue;
            }
            if (++ap == 1)  // add to new pub counter
                scheduledCStateId_->cancel();  // cancel any cState about to be expressed
            if (auto s = subscriptions_.findLM(d.name()); subscriptions_.found(s)) deliver(d, s->second);
            // else print("syncps::onCAdd: no subscription for {}\n", d.name());
        }
        if (ap == 0) return;  // nothing I need in this cAdd, no change to local cState or its schedule

        /* We've delivered all the publications in the cAdd.  There may be
         * additional inbound cAdds for the same cState so sending an updated
         * cState immediately will result in unnecessary duplicates being sent.
         *
         * No longer using deferred delete so need to make sure a new cState is sent without
         * sending before other cAdds responding to the same cState as this one arrive.
         * sendCStateSoon(0 delays a bit (should be min ~ distribution delay for this subnet) and
         * this gets canceled and rescheduled by each new cAdd arrival that has pubs I can use.
         */

        delivering_ = false;
        // If the cAdd resulted in new outbound (locally originated) pubs, cAdd them for any pending peer CStates
        if (initpubs != publications_ && sendCAdd(cState.name())) return;  // sending will schedule an updated cState
        sendCStateSoon(distDelay); // changed local cState send a confirming cState at a randomized delay
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    /**
     * @brief ignore a publication by temporarily adding it to the our iblt
     * XXX fix to add hash to pubs_ so dups can be recognized
     */
    void ignorePub(const rPub& pub) {
        auto hash = hashPub(pub);
        pubs_.iblt().insert(hash);
        oneTime(pubLifetime_ + maxClockSkew, [this, hash] { pubs_.iblt().erase(hash); });
    }

    /**
     * @brief startup related methods start and autoStart
     *
     * 'start' starts up the bottom half (network) communication by registering RIT
     * callbacks for cStates matching this collection's prefix then sending an initial
     * 'cState' to solicit/distribute publications. Since the content of cAdd packets
     * can be encrypted, it's pointless to send a cState before obtaining the decryption
     * key. dct_model sets up an appropriate chain of callbacks such that 'start()' is
     * called after all the prerequisites for syncing this collection have been obtained.
     *
     * 'autoStart' gives the upper level control over whether 'start' is called automatically
     * after 'run()' is called (the default) or if it will be called explicitly
     */
    void start() {
        face_.addToRIT(collName_,
                       [this, ncomp = collName_.nBlks()+1](auto /*prefix*/, auto i) {   // iCb
                           // cState must have one more name component (an iblt) than the collection name
                           // if this handleCState results in sending a cAdd, currently won't schedule a cState, may want to change
                           if (auto n = i.name(); n.nBlks() == ncomp) handleCState(n);
                       },
                       [this](auto ri, auto rd) { // dCb: cAdd response to any active local cState in collName_
                            // print("syncps RIT set Cb received cAdd: {}\n", rd.name());
                            if (! pktSigmgr_.validateDecrypt(rd)) {
                                // print("syncps invalid cAdd: {}\n", rd.name());
                                // Got an invalid cAdd so ignore the pubs it contains.
                                return;
                            }
                            onCAdd(ri, rd);
                        },
                       [this](rName) -> void {
                           registering_ = false;
                           face_.unsuppressCState(rPrefix(collName_/pubs_.iblt().rlEncode())); // force sending initial state
                           sendCState();
                       });
    }

    auto& autoStart(bool yesNo) { autoStart_ = yesNo; return *this; }

    /**
     * @brief start running the event manager main loop (use stop() to return)
     */
    void run() { getDefaultIoContext().run(); }

    /**
     * @brief stop the running the event manager main loop
     */
    void stop() { getDefaultIoContext().stop(); }

    /**
     * @brief methods to change callbacks
     */
    auto& getLifetimeCb(GetLifetimeCb&& getLifetime) { getLifetime_ = std::move(getLifetime); return *this; }
    auto& isExpiredCb(IsExpiredCb&& isExpired) { isExpired_ = std::move(isExpired); return *this; }
    auto& orderPubCb(OrderPubCb&& orderPub) { orderPub_ = std::move(orderPub); return *this; }

    /**
     * @brief methods to change various timer values
     */
    auto& cStateLifetime(std::chrono::milliseconds time) { cStateLifetime_ = time; return *this; }

    auto& pubLifetime(std::chrono::milliseconds time) { pubLifetime_ = time; return *this; }

    auto& pubExpirationGB(std::chrono::milliseconds time) {
        pubExpirationGB_ = time > maxClockSkew? time : maxClockSkew;
        return *this;
    }
};

}  // namespace dct

#endif  // SYNCPS_SYNCPS_HPP
