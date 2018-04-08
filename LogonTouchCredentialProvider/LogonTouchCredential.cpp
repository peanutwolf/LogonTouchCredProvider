#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "LogonTouchCredential.h"
#include "guid.h"


LogonTouchCredential::LogonTouchCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	ZeroMemory(_rgCredentialStrings, sizeof(_rgCredentialStrings));

	_logger = spdlog::get("logger");
}

LogonTouchCredential::~LogonTouchCredential()
{
	SetDeselected();

    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
}


HRESULT LogonTouchCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd, const FIELD_STATE_PAIR* rgfsp){
    HRESULT hr = S_OK;
    _cpus = cpus;

    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++) {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    if (SUCCEEDED(hr)){
        hr = SHStrDupW(L"LogonTouch", &_rgFieldStrings[TFI_LARGETEXT]);
    }
    if (SUCCEEDED(hr)){
        hr = SHStrDupW(L"Use your device to logon", &_rgFieldStrings[TFI_SMALLTEXT]);
    }

	SetCredentialString(LogonTouchCredential::CI_DOMAIN, L"");
	SetCredentialString(LogonTouchCredential::CI_USERNAME, L"");
	SetCredentialString(LogonTouchCredential::CI_PASSWORD, L"");

    return S_OK;
}

int LogonTouchCredential::SetCredentialString(DWORD dwFieldID, PCWSTR value) {
	if (dwFieldID >= sizeof _rgCredentialStrings)
		return -1;

	PWSTR* ppwszStored = &_rgCredentialStrings[dwFieldID];
	if (*ppwszStored) {
		CoTaskMemFree(*ppwszStored);
		*ppwszStored = NULL;
	}
		

	int hr = SHStrDupW(value, ppwszStored);

	return hr;
}

int LogonTouchCredential::ClearCredentialString(DWORD dwFieldID) {
	HRESULT hr = S_OK;

	if (dwFieldID >= sizeof _rgCredentialStrings)
		return -1;

	PWSTR* ppwszStored = &_rgCredentialStrings[dwFieldID];
	if (!*ppwszStored) return 0;

	size_t lenPassword;
	if ((hr = StringCchLengthW(*ppwszStored, 128, &(lenPassword))) < 0) {
		return hr;
	}

	SecureZeroMemory(*ppwszStored, lenPassword * sizeof(**ppwszStored));
	CoTaskMemFree(*ppwszStored);
	*ppwszStored = NULL;

	SetCredentialString(dwFieldID, L"");

	return hr;
}

void LogonTouchCredential::SetCredentialsArmed(bool armed) {
	_pCredentialsArmedForRequest = armed;
	_logger->debug("Settings credentials armed state=[{}]", armed);
}

bool LogonTouchCredential::GetCredentialArmed() {
	return _pCredentialsArmedForRequest;
}

HRESULT LogonTouchCredential::Advise(ICredentialProviderCredentialEvents* pcpce){
    if (_pCredProvCredentialEvents != NULL){
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();

    return S_OK;
}

HRESULT LogonTouchCredential::UnAdvise(){
    if (_pCredProvCredentialEvents){
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

HRESULT LogonTouchCredential::SetSelected(BOOL* pbAutoLogon) {
	*pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT LogonTouchCredential::SetDeselected()
{
    HRESULT hr = S_OK;

	if ((hr = ClearCredentialString(CI_DOMAIN)) < 0) {
		return hr;
	}else if ((hr = ClearCredentialString(CI_USERNAME)) < 0) {
		return hr;
	}else if ((hr = ClearCredentialString(CI_PASSWORD)) < 0) {
		return hr;
	}

    return hr;
}

HRESULT LogonTouchCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis){
    HRESULT hr;
    
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) && pcpfs && pcpfis){
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        hr = S_OK;
    }else{
        hr = E_INVALIDARG;
    }
    return hr;
}

HRESULT LogonTouchCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz){
    HRESULT hr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz){
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }else{
        hr = E_INVALIDARG;
    }

    return hr;
}

HRESULT LogonTouchCredential::GetBitmapValue(
    DWORD dwFieldID, 
    HBITMAP* phbmp){
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(phbmp);
	return E_NOTIMPL;
}

HRESULT LogonTouchCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pdwAdjacentTo);

	return E_NOTIMPL;
}

HRESULT LogonTouchCredential::SetStringValue(
    DWORD dwFieldID, 
    PCWSTR pwz      
    )
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pwz);

	return E_NOTIMPL;
}

HRESULT LogonTouchCredential::GetCheckboxValue(
    DWORD dwFieldID, 
    BOOL* pbChecked,
    PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT LogonTouchCredential::GetComboBoxValueCount(
    DWORD dwFieldID, 
    DWORD* pcItems, 
    DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT LogonTouchCredential::GetComboBoxValueAt(
    DWORD dwFieldID, 
    DWORD dwItem,
    PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT LogonTouchCredential::SetCheckboxValue(
    DWORD dwFieldID, 
    BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT LogonTouchCredential::SetComboBoxSelectedValue(
    DWORD dwFieldId,
    DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT LogonTouchCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

HRESULT LogonTouchCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

    KERB_INTERACTIVE_LOGON kil;
    ZeroMemory(&kil, sizeof(kil));
    HRESULT hr;
	
	if (wcslen(_rgCredentialStrings[CI_DOMAIN]) == 0) {
		WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD cch = ARRAYSIZE(wsz);

		if (!GetComputerNameW(wsz, &cch)) {
			DWORD dwErr = GetLastError();
			return HRESULT_FROM_WIN32(dwErr);
		}
		SetCredentialString(CI_DOMAIN, wsz);
	}

	PWSTR pwzProtectedPassword;
	KERB_INTERACTIVE_UNLOCK_LOGON kiul;
	ULONG ulAuthPackage;

	if ((hr = ProtectIfNecessaryAndCopyPassword(_rgCredentialStrings[CI_PASSWORD], _cpus, &pwzProtectedPassword)) < 0) {
		CoTaskMemFree(pwzProtectedPassword);
		return hr;
	}

	if ((hr = KerbInteractiveUnlockLogonInit(_rgCredentialStrings[CI_DOMAIN], _rgCredentialStrings[CI_USERNAME], pwzProtectedPassword, _cpus, &kiul)) < 0) {
		CoTaskMemFree(pwzProtectedPassword);
		return hr;
	}

	if((hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization)) < 0){
		CoTaskMemFree(pwzProtectedPassword);
		return hr;
	}

	if ((hr = RetrieveNegotiateAuthPackage(&ulAuthPackage)) < 0) {
		CoTaskMemFree(pwzProtectedPassword);
		return hr;
	}

	pcpcs->ulAuthenticationPackage = ulAuthPackage;
	pcpcs->clsidCredentialProvider = CLSID_TouchProvider;

	*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

	SetCredentialsArmed(false);

	return hr;
}
struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

HRESULT LogonTouchCredential::ReportResult(
    NTSTATUS ntsStatus, 
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    *ppwszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

	_logger->info("[ReportResult] received ntsStatus=[{}], ntsSubstatus=[{}]", ntsStatus, ntsSubstatus);

    DWORD dwStatusInfo = (DWORD)-1;
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++){
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus){
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo){
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText))){
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus))){
        if (_pCredProvCredentialEvents){
			SetDeselected();
        }
    }

    return S_OK;
}
