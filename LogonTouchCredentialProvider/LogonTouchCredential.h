
#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include "helpers.h"
#include "dll.h"
#include "resource.h"

class LogonTouchCredential : public ICredentialProviderCredential
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
        if (ppv != NULL)
        {
            if (IID_IUnknown == riid ||
                IID_ICredentialProviderCredential == riid)
            {
                *ppv = static_cast<IUnknown*>(this);
                reinterpret_cast<IUnknown*>(*ppv)->AddRef();
                hr = S_OK;
            }
            else
            {
                *ppv = NULL;
                hr = E_NOINTERFACE;
            }
        }
        else
        {
            hr = E_INVALIDARG;
        }
        return hr;
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
                                    PWSTR* ppwszOptionalStatusText, 
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, 
                                NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText, 
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

  public:
	  enum CREDENTIAL_ITEMS {
		CI_DOMAIN      = 0,
		CI_USERNAME    = 1,
		CI_PASSWORD    = 2,
		CI_NUM_FIELDS  = 3,
	  };

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp);

	int SetCredentialString(DWORD dwFieldID, PCWSTR value);
	int ClearCredentialString(DWORD dwFieldID);

	void SetCredentialsArmed(bool armed);
	bool GetCredentialArmed();

    LogonTouchCredential();

    virtual ~LogonTouchCredential();

  private:
    LONG                                  _cRef;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus; 

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[TFI_NUM_FIELDS];  

    FIELD_STATE_PAIR                      _rgFieldStatePairs[TFI_NUM_FIELDS];          

    PWSTR                                 _rgFieldStrings[TFI_NUM_FIELDS];              
                                                                                        
	PWSTR								 _rgCredentialStrings[CI_NUM_FIELDS];
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;    
	bool								 _pCredentialsArmedForRequest;
};
