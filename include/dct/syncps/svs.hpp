/*
 * Copyright (c) 2019-2020,  Pollere Inc.
 * Pollere authors at info@pollere.net
 *
 * This file is part of syncps (NDN sync for pubsub).
 *
 * syncps is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * syncps is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * syncps, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP

#include <map>

#include "ndn-cxx-ind.hpp"
#include <ndn-svs/svspubsub.hpp>

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/util/scheduler.hpp>

#include "dct/sigmgrs/sigmgr.hpp"
#include "../schema/certstore.hpp"

#include "svs_security.hpp"

namespace syncps
{
INIT_LOGGER("syncps");

using Name = ndn_ind::Name;         // type of a name
using Publication = ndn_ind::Data;  // type of a publication
using ScopedEventId = ndn_ind::scheduler::ScopedEventId; // scheduler events

/**
 * @brief app callback when new publications arrive
 */
using UpdateCb = std::function<void(const Publication&)>;
/**
 * @brief app callback when publication is seen on another node's list
 */
using PublishCb = std::function<void(const Publication&, bool)>;
/**
 * @brief app callback to test if publication is expired
 */
using IsExpiredCb = std::function<bool(const Publication&)>;

/**
 * @brief sync a lifetime-bounded set of publications among
 *        an arbitrary set of nodes.
 *
 * Application should call 'publish' to add a new publication to the
 * set and register an UpdateCallback that is called whenever new
 * publications from others are received. Publications are automatically
 * deleted (without notice) at the end their lifetime.
 *
 * Publications are named, signed objects (ndn_ind::Data). The last component of
 * their name is a version number (local ms clock) that is used to bound the
 * pub lifetime. This component is added by 'publish' before the publication
 * is signed so it is protected against replay attacks. App publications
 * are signed by pubCertificate and external publications are verified by
 * pubValidator on arrival.
 */

class SyncPubsub
{
  public:
    struct Error : public std::runtime_error { using std::runtime_error::runtime_error; };

    static ndn::Face& getFace() {
        static ndn::Face* face{};
        if (face == nullptr) {
            face = new ndn::Face();
        }
        return *face;
    }

    /**
     * @brief constructor
     *
     * Registers syncPrefix in NFD and sends a sync interest
     *
     * @param face application's face
     * @param syncPrefix The ndn name prefix for sync interest/data
     * @param wsig The sigmgr for Data packet signing and validation
     * @param psig The sigmgr for Publication validation
     */
    SyncPubsub(Name syncPrefix, SigMgr& wsig, SigMgr& psig, const ndn_ind::Name& pubName) : SyncPubsub(getFace(), syncPrefix, wsig, psig, pubName) {}

    SyncPubsub(Name syncPrefix, SigMgr& wsig, SigMgr& psig, const certStore& cs_) : SyncPubsub(getFace(), syncPrefix, wsig, psig, cs_.get(cs_.Chains()[0]).getName().getPrefix(-4)) {}

    SyncPubsub(ndn::Face& face, Name syncPrefix, SigMgr& wsig, SigMgr& psig, const ndn_ind::Name pubName)
        : m_face(face),
          m_syncPrefix(std::move(syncPrefix)),
          m_scheduler(m_face.getIoService()),
          m_sigmgr(wsig),
          m_pubSigmgr(psig),
          staticModuleLogger{log4cxx::Logger::getLogger(m_syncPrefix.toUri())}
    {
        ndn::svs::SecurityOptions opts(m_keyChain);
        opts.interestSigner->signingInfo.setSigningHmacKey("hello");
        opts.validator = std::make_shared<DCTValidator>(m_sigmgr);
        opts.dataSigner = std::make_shared<DCTSigner>(m_sigmgr);
        opts.encapsulatedDataValidator = std::make_shared<DCTValidator>(m_pubSigmgr);

        m_svs = std::make_shared<ndn::svs::SVSPubSub>(
            ndn_ind::toCxx(m_syncPrefix),
            ndn_ind::toCxx(pubName),
            m_face,
            [](const auto& /*v*/) {},
            opts
        );
    }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and
     * lives for at most pubLifetime.
     * Assume Publications arrive signed.
     *
     * @param pub the object to publish
     */
    uint32_t publish(Publication&& pub)
    {
        auto h = hashPub(pub);
        m_svs->publishData(ndn_ind::toCxx(pub));
        return h;
    }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and
     * lives for at most pubLifetime. This version
     * takes a callback so publication can be confirmed
     * or failure reported so "at least once" or other
     * semantics can be built into shim. Sets callback.
     *
     * @param pub the object to publish
     */
    uint32_t publish(Publication&& pub, PublishCb&& cb)
    {
        auto h = publish(std::move(pub));
        if (h != 0) {
            m_scheduler.schedule(std::chrono::milliseconds(1), [cb, pub] {
                cb(pub, true);
            });
        }
        return h;
    }

    /**
     * @brief subscribe to a subtopic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     *
     * @param  topic the topic
     */
    SyncPubsub& subscribeTo(const Name& topic, UpdateCb&& cb)
    {
        // Proxy to SVS
        m_subscription[topic] = m_svs->subscribeToPrefix(ndn_ind::toCxx(topic),
          [this, cb] (ndn::svs::SVSPubSub::SubscriptionData subData) {
              auto indData = ndn::toInd(subData.data);
              return cb(indData);
          });

        return *this;
    }

    /**
     * @brief unsubscribe to a subtopic
     *
     * A subscription to 'topic', if any, is removed.
     *
     * @param  topic the topic
     */
    SyncPubsub& unsubscribe(const Name& topic)
    {
        m_svs->unsubscribe(m_subscription.at(topic));
        m_subscription.erase(topic);
        return *this;
    }

    /**
     * @brief start running the event manager main loop
     *
     * (usually doesn't return)
     */
    void run() { m_face.processEvents(); }

    /**
     * @brief schedule a callback after some time
     *
     * This lives here to avoid exposing applications to the complicated mess
     * of NDN's relationship to Boost
     *
     * @param after how long to wait (in nanoseconds)
     * @param cb routine to call
     */
    ScopedEventId schedule(std::chrono::nanoseconds after,
                           const std::function<void()>& cb)
    {
        return m_scheduler.schedule(after, cb);
    }

  private:

    uint32_t hashPub(const Publication& pub) const
    {
        const auto& b = *pub.wireEncode();
        return ndn_ind::CryptoLite::murmurHash3(0, b.data(), b.size());
    }

  private:
    ndn::Face& m_face;
    ndn::KeyChain m_keyChain;
    std::shared_ptr<ndn::svs::SVSPubSub> m_svs;

    ndn_ind::Name m_syncPrefix;
    ndn_ind::scheduler::Scheduler m_scheduler;

    std::map<const Name, uint32_t> m_subscription{};
    SigMgr& m_sigmgr;               // SyncData packet signing and validation
    SigMgr& m_pubSigmgr;            // Publication validation
    log4cxx::LoggerPtr staticModuleLogger;
};

}  // namespace syncps

#endif  // SYNCPS_SYNCPS_HPP
