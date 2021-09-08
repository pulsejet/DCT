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
            if (failureCb)
            {
                failureCb(data, ndn::security::ValidationError(100, "DCT Validation Fail"));
            }
            return;
        }
    }

    void
    validate(const ndn::Interest& interest,
             const ndn::security::InterestValidationSuccessCallback& successCb,
             const ndn::security::InterestValidationFailureCallback& failureCb)
    {
        if (interest.isSigned())
        {
            ndn::Block block = interest.getSignatureValue().blockFromValue();
            ndn_ind::Data indData;
            indData.wireDecode(block.wire(), block.size());
            indData.setName(ndn::toInd(interest.getName().getPrefix(-1)));

            if (m_sigmgr.validateDecrypt(indData))
            {
                // std::cout << "IVP: " << interest.getName().getPrefix(-2) << std::endl;
                return successCb(interest);
            }
            else
            {
                // std::cout << "IVF: " << interest.getName().getPrefix(-2) << std::endl;
                if (failureCb)
                {
                    failureCb(interest, ndn::security::ValidationError(100, "DCT Validation Fail"));
                }
                return;
            }
        }
        else
        {
            if (failureCb)
            {
                failureCb(interest, ndn::security::ValidationError(100, "No signature on interest"));
            }
            return;
        }

        return successCb(interest);
    }

private:
    SigMgr& m_sigmgr;
};

class DCTSigner : public ndn::svs::BaseSigner
{
public:
    DCTSigner(SigMgr& wsig)
    : m_sigmgr(wsig)
    {
        signingInfo.setSigningKeyName("/ndn");
    }

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

    void
    sign(ndn::Interest& interest) const override
    {
        ndn_ind::Data indData(ndn::toInd(interest.getName().getPrefix(-1)));
        indData.setContent(interest.getApplicationParameters().wire(), interest.getApplicationParameters().size());
        if (!m_sigmgr.sign(indData)) {
            return;
        };

        indData.setName("/");
        auto blob = indData.wireEncode();

        ndn::SignatureInfo si;
        si.setSignatureType(ndn::tlv::SignatureTypeValue::SignatureSha256WithEcdsa);
        interest.setSignatureInfo(si);
        interest.setSignatureValue(ndn::Block(blob.buf(), blob.size()).getBuffer());
    }

private:
    SigMgr& m_sigmgr;
};

#endif
