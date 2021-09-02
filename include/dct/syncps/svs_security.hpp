#ifndef CXX_VALIDATOR_HPP
#define CXX_VALIDATOR_HPP

#include <ndn-svs/security-options.hpp>
#include "dct/sigmgrs/sigmgr.hpp"
#include "ndn-cxx-ind.hpp"

class DCTValidator : public ndn::svs::BaseValidator
{
public:
    DCTValidator(SigMgr& wsig) :
        m_sigmgr(wsig)
    {}

    void
    validate(const ndn::Data& data,
             const ndn::security::DataValidationSuccessCallback& successCb,
             const ndn::security::DataValidationFailureCallback& failureCb)
    {
        auto indData = ndn::toInd(data);
        if (m_sigmgr.validateDecrypt(indData)) {
            return successCb(ndn_ind::toCxx(indData));
        } else {
            return failureCb(data, ndn::security::ValidationError(100, "DCT Validation Fail"));
        }
    }

private:
    SigMgr& m_sigmgr;
};

class DCTSigner : public ndn::svs::BaseSigner
{
public:
    DCTSigner(SigMgr& wsig) :
        m_sigmgr(wsig)
    {}

    void
    sign(ndn::Data& data) const override
    {
        auto indData = ndn::toInd(data);
        if (!m_sigmgr.sign(indData)) {
            std::cerr << "Failed to sign data with DCT Signer: " << data.getName() << std::endl;
        }
        auto wire = indData.wireEncode();
        data.wireDecode(ndn::Block(wire.buf(), wire.size()));
    }

private:
    SigMgr& m_sigmgr;
};

#endif
