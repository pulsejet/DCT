#ifndef SBT_SHIM_HPP
#define SBT_SHIM_HPP
/*
 * sbtShim.hpp: publish-subscribe sentinel shim
 */

#include <algorithm>
#include <bitset>
#include <functional>
#include <getopt.h>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include "dct/syncps/syncps.hpp"
#include "dct/schema/dct_model.hpp"

using namespace syncps;

/*
 * This file contains the methods implementing Sentinel Bespoke Transport shim.
 * It is a self-contained, 'header-only' library.
 *
 * sbtShim provides an example API between a Zeek adaptor and the syncps
 * protocol. An adaptor for Zeek should create one sbtShim and pass in a
 * callback to invoke for each new message received. This code was made
 * to implement and test concepts for SBT and has always been intended to
 * be passed on to a professional programmer.
 *
 * Messages are the application layer frame and may exceed the size of
 * a network layer publication. This shim takes care of segmenting messages
 * into the publication pieces and assembling publication pieces into messages
 * and only passes messages and indications about messages to the application.
 */

using error = std::runtime_error;
static constexpr size_t MAX_CONTENT= 768; //max content size in bytes, <= maxPubSize in syncps.hpp
static constexpr size_t MAX_PIECES = 64;  //max pieces of a msg, <= maxDifferences in syncps.hpp

using Arglist = std::unordered_map<std::string, std::string>;

using Piece = std::vector<uint8_t>;
using timeList = std::unordered_map<std::string, const std::chrono::milliseconds>;
using pieceList = std::vector<Piece>;
using msgHndlr = std::function<void(const pieceList&, const Arglist&)>;
using Timer = ndn::scheduler::ScopedEventId;
using TimerCb = std::function<void()>;
using PieceCnt = uint16_t;
using MsgID = uint32_t;
using MsgInfo = std::unordered_map<MsgID,std::bitset<64>>;
using MsgCache = std::unordered_map<MsgID,pieceList>;
using msgPiece = DCTmodel::sPub;

// This shim sends to all sbt nodes on this broadcast network
// The targets are set for each message in publishMessage()
struct sbtShim {
    DCTmodel m_pb;
    Name m_pubpre{};     // publication prefix
    MsgInfo m_pending{};  // unconfirmed published messages
    MsgInfo m_incomplete{};  // incomplete received messages
    MsgCache m_reassemble{};  // received messages reassembly
    Timer m_timer;
    std::function<void()> m_initCb;

    // shim needs to know its "role". This should come from the name of the signing cert in its bundle

    sbtShim(std::string_view bootstrap) : m_pb(bootstrap), m_pubpre{m_pb.pubPrefix()}  { }

    void run() { m_pb.run(); }
    const auto& pubPrefix() const noexcept { return m_pubpre; }

    //these two rely on knowledge from trust schema specifying layout of signing cert
    std::string_view myRole() const noexcept {
        // the role is in the signing cert, 6 components back the end
        auto& cs = m_pb.certs();
        auto v = cs[cs.Chains()[0]].getName()[-6].getValue();
        return std::string_view((const char*)v.buf(), v.size());
    }
    std::string_view myId() const noexcept {
        // the identifier (within the role) is in the signing cert, 5 components back the end
        // this value appears in the location field for subtopics specific to this entity
        auto& cs = m_pb.certs();
        auto v = cs[cs.Chains()[0]].getName()[-5].getValue();
        return std::string_view((const char*)v.buf(), v.size());
    }

    /*
     * If set up is necessary for an application to publish or receive publications,
     * e.g. the acquisition of keys, the m_pb.start function will handle that and call
     * back with a success or fail indicator. If no initialization is required, the callback
     * is immediate.
     *
     * If m_pb.start results in a callback indicating success, the passed-in cb is invoked.
     * If failure is indicated, the shim exits.
     * Since some key distribution failures can take a long time (order of key lifetime), the
     * application might want to set a timeout before invoking this method.
     */

    void init(std::function<void()>&& icb)
    {
        m_initCb = std::move(icb);
        m_pb.start([this](bool success){
                if(!success) {
                    std::cerr << "sbtShim: cannot initialize" << std::endl;
                    exit(1);
                } else {
                    m_initCb();
                }
            }, [this]() {   //only a manager can be a key maker
                if(myRole() == "manager") return true;
                else    return false;
            });
    }

    /*
     * confirmPiece method to pass to syncps to set as "on Published" callback
     * if "at least once" semantics desired. Confirms piece made it to Collection.
     * success = true means appeared in some other node's IBLT; false means
     * publication timed out without appearing in some other node's IBLT.
     *
     * When all k of n pieces are confirmed published, could invoke
     * callback to the shim owner, either set this at shim
     * creation time or when message is passed for publication.
     */
    void confirmPiece(const msgPiece& p, bool success)
    {
        MsgID  mId = p.number("msgID"); 
        PieceCnt k = p.number("pCnt"), n{1u};
        if (k != 0) {
            // Don't need to keep state for single piece msgs but multi-piece succeed
            // only if all their pieces arrive and fail otherwise. Keep per-msg arrival
            // state in a bitmap that's created on-demand and erased on completion or timeout.
            n = k & 255;
            if (success) {
                m_pending[mId].set(k >> 8);
                if (m_pending[mId].count() != n) return; // all pieces haven't arrived
            }
            // either msg complete or piece timed out so delivery has failed - delete msg state
            k = m_pending[mId].count();
            if (m_pending.contains(mId)) m_pending.erase(mId);
        }
        if (success) {
            _LOG_INFO("confirmPiece: msgID " << mId << "(" << n << " pieces) arrived, RTT " << p.timeDelta("mts"));
            //if a confirmation cb set by app, would go here
        } else {
            _LOG_INFO("confirmPiece: msgID " << mId << " " << n - k << " pieces (of " << n << ") timed out");
            //if a timeout cb set by app, would go here
        }
    }

    /*
     * Zeek adaptor calls this method and passes the message to be published.
     * The argument list must include a target (logs, control, cluster) and topic.
     * May include args.
     *
     * The message has to be broken into content-sized pieces for publication.
     * All pieces have the same message ID and timestamp.
     * Could pass a callback function pointer to track when all pieces published
     *
     * returns 1 if can't form publication(s), 0 otherwise
     */
    int publishMsg(const std::vector<uint8_t>& msg, const Arglist& a)
    {
        /*
         * Set up and publish  Publication(s)
         * msgID is an uint32_t hash of the message
         * incorporating process ID and timestamp to make unique
         */
        auto size = msg.size();
        auto mts = std::chrono::system_clock::now();
        uint64_t tms = duration_cast<std::chrono::microseconds>(mts.time_since_epoch()).count();
        std::vector<uint8_t> emsg;
        for(size_t i=0; i<sizeof(tms); i++)
            emsg.push_back( tms >> i*8 );
        emsg.insert(emsg.end(), myRole().begin(), myRole().end());
        emsg.insert(emsg.end(), myId().begin(), myId().end());
        emsg.insert(emsg.end(), msg.begin(),msg.end());
        std::array<uint8_t, 4> h;        //so fits in uint32_t
        crypto_generichash(h.data(), h.size(), emsg.data(), emsg.size(), NULL, 0);
        uint32_t mId = h[0] | h[1] << 8 | h[2] << 16 | h[3] << 24;
        size_t n = (size + (MAX_CONTENT - 1)) / MAX_CONTENT;
        //pCnt forces n < 256, iblt is sized for 80 but 64 fits in an int bitset
        if(n > MAX_PIECES) throw error("publishMsg: message too large");
        auto pCnt = n > 1? n + 256 : 0;
        std::span m(msg.data(), size);
        try {
            for (auto off = 0u; off < size; off += MAX_CONTENT) {
                auto len = std::min(size - off, MAX_CONTENT);
                m_pb.publish(m_pb.pub(m.subspan(off, len), "target", a.at("target"),
                                    "topic", a.at("topic"), "args", a.at("args"),
                                    "msgID", mId, "pCnt", pCnt, "mts", mts),
                           [this](auto p, bool s) { confirmPiece(p, s); });
                pCnt += 256;
            }
        } catch(const std::exception& e) {
            std::cerr << e.what() << std::endl;
            std::cerr << "args: target " << a.at("target") << " topic " << a.at("topic") << " args " << a.at("args") << std::endl;
            throw error("publishMsg failed");
        }

        return 0;
    }

    // currently used to delay exit of message publisher and implement an initialization timeout
    void setTimeOut(std::chrono::nanoseconds dly, const TimerCb& cb) { m_timer = schedule(dly, cb); }
    void cancelTimeOut() { m_timer = schedule(std::chrono::nanoseconds(0), [](){return;});}

    /*
     * Called when a new publication (piece of message) is received. 
     * Parse the publication name and use to test for all parts of message.
     * A message is uniquely identified by its msgID and its timestamp
     * and each name is identical except for the k in the k out of n pCnt.
     * When all n pieces received,reassemble into a message and callback
     * the message handler.
     *
     * This assumes one shim to subscribe to all publications
     *
     * Extract n from the piece name: n=0 means only this piece,
     * otherwise n pieces in total message. Each piece has the same
     * name components except for pCnt field.
     * When all k of n publications of message have been received, invoke
     * callback. 
     */
    void receivePiece(const msgPiece& p, const msgHndlr& mh)
    {
        PieceCnt k = p.number("pCnt"), n = 1u;
        if (k != 0) {
            n = k & 255;
            k >>= 8;
            if (k > n || k == 0) {
                _LOG_WARN("receivePiece: msgID " << p.number("msgID") << " piece " << k << " > " << n << " pieces");
                return;
            }
            --k;
        }
        pieceList msgPieces(n);
        if(n > 1) {
            // make sure the reassembly vector for this piece is big enough to hold
            // all the pieces then add the current piece to it. 
            MsgID mId = p.number("msgID");
            if (m_reassemble[mId].size() < n) m_reassemble[mId].resize(n);
            m_reassemble[mId][k] = *p.getContent();
            // if haven't got all the pieces just return. Otherwise swap the
            // pieces into the local vector & delete the reassembly map entry.
            m_incomplete[mId].set(k);
            if (m_incomplete[mId].count() != n) return;
            msgPieces = m_reassemble[mId];
            m_reassemble.erase(mId);
            m_incomplete.erase(mId);
        } else { 
            msgPieces[0] = Piece(*p.getContent());
        }
        _LOG_INFO("receivePiece: msgID " << p.number("msgID") << "(" << n << " pieces) delivered in " << p.timeDelta("mts") << " sec.");
        Arglist msgArgs{};
        msgArgs["target"] = p["target"];
        msgArgs["topic"] = p["topic"];
        msgArgs["args"] = p["args"];
        msgArgs["msrc"] = p["_role"] + p["_Id"];
        msgArgs["mts"] =  ndn::toIsoString(p.time("mts"), true);
        mh(msgPieces, msgArgs);
    }

    /*
     * Subscribe to sub topic and wait for an incoming Publication which
     * holds a piece of a message. Receiving a piece causes a callback
     * to receivePiece, passing the Publication and the msgHndlr callback
     * that gets called for a complete message to be passed to application.
     * With multiple topics per shim, the subscribed portion could include
     * target, topic, args and other parts of Publication name.
     *
     * Subscriptions always include the Publication prefix for this shim
     * The type of the entity determines its subscribed (sub)topics.
     * (pending clarification from Operant)
     * It's possible to subscribe to pubPrefix() + target + <more>
     * but everything goes to the same callback.
     */

    sbtShim& waitForMsg(const msgHndlr& mh)
    {
        if(myRole() == "worker") {
            std::string id (myId());
            std::string subtopic (pubPrefix().toUri() + "/cluster/worker");
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
            subtopic.assign(pubPrefix().toUri() + "/cluster/node/worker" + id);
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
            subtopic.assign(pubPrefix().toUri() + "/control/" + myHexID());
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
        } else if (myRole() == "manager") {
            auto subtopic = pubPrefix().toUri() + "/cluster/manager";
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
            subtopic = pubPrefix().toUri() + "/control/" + myHexID();
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
            subtopic = pubPrefix().toUri() + "/logs";
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
        } else if (myRole() == "proxy") {
            std::string id (myId());
            auto subtopic = pubPrefix().toUri() + "/cluster/node/proxy" + id;
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
            subtopic = pubPrefix().toUri() + "/control/" + myHexID();
            m_pb.subscribeTo(subtopic, [this,mh](auto p) { receivePiece(p, mh); });
        } else {
            throw error("waitForMsg: illegal entity identity");
            exit(1);
        }
        return *this;
    }

    Timer schedule(std::chrono::nanoseconds d, const TimerCb& cb) { return m_pb.schedule(d, cb); }

    //this is a place holder for the ids in RK's document which
    // differ only in the number after the hash
    const std::string myHexID() {
        if(myRole() == "worker")    //"local worker" hexid
            return "4947C1C8683F9745FECEDF7176CCDE5FB9288C00#55642";
        else if(myRole() == "manager")
            return "4947C1C8683F9745FECEDF7176CCDE5FB9288C00#55545";
        else if(myRole() == "proxy")
            return "4947C1C8683F9745FECEDF7176CCDE5FB9288C00#55594";
        else return "no HexID available";
    }
};

#endif
