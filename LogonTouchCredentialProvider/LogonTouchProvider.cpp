#include <credentialprovider.h>
#include "LogonTouchCredential.h"
#include "LogonTouchProvider.h"
#include "CommandServer.h"
#include "guid.h"

LogonTouchProvider::LogonTouchProvider():
    _cRef(1)
{
    DllAddRef();

	_logger = spdlog::get("logger");
	_logger->debug("Create instance of LogonTouchProvider");

    _pcpe = NULL;
	_pCommandServer = NULL;
    _pCredential = NULL;
}

LogonTouchProvider::~LogonTouchProvider()
{
    if (_pCredential != NULL) {
        _pCredential->Release();
        _pCredential = NULL;
    }

	if (_pCommandServer != NULL) {
		_pCommandServer->ServerStop();
		delete _pCommandServer;
		_pCommandServer = NULL;
	}

	_logger->debug("Release instance of LogonTouchProvider");

    DllRelease();
}

long LogonTouchProvider::OnCredentialsReceived(shared_ptr<ClientCredentialImpl> credential)
{
	if (_pcpe == NULL || credential == nullptr)
		return -1;

	_logger->info("OnCredentialsReceived received credentials");

	wstring ldomain(credential->domain.begin(), credential->domain.end());
	wstring luser(credential->username.begin(), credential->username.end());
	wstring lpass(credential->password.begin(), credential->password.end());

	_pCredential->SetCredentialString(LogonTouchCredential::CI_DOMAIN  , ldomain.c_str());
	_pCredential->SetCredentialString(LogonTouchCredential::CI_USERNAME, luser.c_str());
	_pCredential->SetCredentialString(LogonTouchCredential::CI_PASSWORD, lpass.c_str());
	_pCredential->SetCredentialsArmed(true);
    return _pcpe->CredentialsChanged(_upAdviseContext);
}

HRESULT LogonTouchProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags){
    UNREFERENCED_PARAMETER(dwFlags);
    static HRESULT hr = E_FAIL;

    switch (cpus){
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:  
	case CPUS_CREDUI:
        _cpus = cpus;

		if (_pCommandServer || _pCredential)
			break;

		_pCommandServer = new CommandServer();
		_pCredential = new LogonTouchCredential();

		if (!_pCommandServer || !_pCredential) {
			hr = E_OUTOFMEMORY;
			break;
		}
		try {
			if (_pCommandServer->Initialize(this) != 0) {
				_logger->error("Failed to initialize CommandServer");
				hr = E_FAIL;
				break;
			}
			_pCommandServer->ServerStart();
		}catch (const std::runtime_error& re) {
			_logger->error("Runtime error occurred while starting CommandServer {}", re.what());
			hr = E_FAIL;
			break;
		}catch (const std::exception& ex) {
			_logger->error("Error occurred while starting CommandServer {}", ex.what());
			hr = E_FAIL;
			break;
		}catch (...) {
			_logger->error("Exception caught when try CommandServer start");
			hr = E_FAIL;
			break;
		}

		if (_pCredential->Initialize(_cpus, s_rgTouchProvFieldDescriptors, s_rgTouchStatePairs) < 0) {
			_logger->error("Failed to initialize LogonTouchCredential");
			hr = E_FAIL;
			break;
		}

		hr = S_OK;

        break;
    case CPUS_CHANGE_PASSWORD:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

	_logger->info("SetUsageScenario for scenario=[{}] res=[{}]", cpus, hr);
    return hr;
}

STDMETHODIMP LogonTouchProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs){
    UNREFERENCED_PARAMETER(pcpcs);
    return E_NOTIMPL;
}

HRESULT LogonTouchProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext){
    if (_pcpe != NULL){
        _pcpe->Release();
    }
    _pcpe = pcpe;
    _pcpe->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

HRESULT LogonTouchProvider::UnAdvise()
{
    if (_pcpe != NULL){
        _pcpe->Release();
        _pcpe = NULL;
    }
    return S_OK;
}

HRESULT LogonTouchProvider::GetFieldDescriptorCount(DWORD* pdwCount){
	*pdwCount = TFI_NUM_FIELDS;
    return S_OK;
}

HRESULT LogonTouchProvider::GetFieldDescriptorAt(
    DWORD dwIndex, 
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd){    
    HRESULT hr;

	if ((dwIndex < TFI_NUM_FIELDS) && ppcpfd){
		hr = FieldDescriptorCoAllocCopy(s_rgTouchProvFieldDescriptors[dwIndex], ppcpfd);
	}else{
		hr = E_INVALIDARG;
	}

    return hr;
}

HRESULT LogonTouchProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault){
    *pdwCount = _pCredential->GetCredentialArmed() == true ? 1 : 0;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = _pCredential->GetCredentialArmed();

	_logger->debug("GetCredentialCount pdwCount=[{}], pbAutoLogonWithDefault=[{}]", *pdwCount, *pbAutoLogonWithDefault);

    return S_OK;
}


HRESULT LogonTouchProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc){
    HRESULT hr;
	 if ((dwIndex == 0) && ppcpc){
		hr = _pCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }else{
        hr = E_INVALIDARG;
    }
        
    return hr;
}

HRESULT LogonTouchProvider_CreateInstance(REFIID riid, void** ppv){
    HRESULT hr;
	string install_path;

	logontouch::getLogonTouchRegParam("", install_path);
	auto logger = spdlog::combined_logger_st_safe("logger", install_path+"credprov.log", 1024 * 1024 * 5, 3);
	logger->flush_on(spdlog::level::trace);
	logger->set_level(spdlog::level::trace);
	spdlog::register_logger(logger);

	logger->info("/----------------------------------------------------------/");

    LogonTouchProvider* pProvider = new LogonTouchProvider();

    if (pProvider){
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }else{
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}
