
#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>

#include "CommandServer.h"
#include "ServerConfig.h"
#include "LogonTouchCredential.h"
#include "helpers.h"

// Forward references for classes used here.
class LogonTouchCredential;
class CMessageCredential;
class CommandServer;

class LogonTouchProvider : public ICredentialProvider
{
  public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        return _cRef++;
    }
    
    STDMETHOD_(ULONG, Release)()
    {
        LONG cRef = _cRef--;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
    {
        HRESULT hr;
        if (IID_IUnknown == riid || 
            IID_ICredentialProvider == riid)
        {
            *ppv = this;
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
        }
        else
        {
            *ppv = NULL;
            hr = E_NOINTERFACE;
        }
        return hr;
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, 
                                   __out ICredentialProviderCredential** ppcpc);

    friend HRESULT LogonTouchProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

public:
    long OnCredentialsReceived(shared_ptr<ClientCredentialImpl> credential);

  protected:
    LogonTouchProvider();
    __override ~LogonTouchProvider();
    
private:
    LONG                        _cRef;                  // Reference counter.
	CommandServer               *_pCommandServer;
    LogonTouchCredential        *_pCredential;          
    ICredentialProviderEvents   *_pcpe;                 // Used to tell our owner to re-enumerate credentials.
    UINT_PTR                    _upAdviseContext;       // Used to tell our owner who we are when asking to 
                                                        // re-enumerate credentials.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
};
