
#include "CommandServer.h"
#include "ServerConfig.h"
#include "Base64.h"

#include <memory>
#include <cstdlib>
#include <asio\buffer.hpp>
#include <Windows.h>
#include <Winreg.h>
#include <thread>

using namespace std;


LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
{
	strValue = strDefaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}

int getLogonTouchRegParam(const string &param, string &path) {
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\LogonTouch", 0, KEY_READ, &hKey);
	if (lRes != ERROR_SUCCESS) return -1;

	std::wstring str_tmp;
	std::wstring param_tmp(param.begin(), param.end());
	GetStringRegKey(hKey, param_tmp, str_tmp, L"");
	path.assign(str_tmp.begin(), str_tmp.end());

	RegCloseKey(hKey);

	return 0;
}

void server_thread(LongonTouchServer *server) {
	server->Server_Start();
}


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, allocator<char> > secure_string;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void aes_decrypt(const unsigned char key[128], const unsigned char iv[128], const string& ctext, string& ptext){
	using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
	EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	auto plaintext = std::make_unique<unsigned char[]>(ctext.size());
	int len;
	int plaintext_len;

	if(1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv))
		throw std::runtime_error("EVP_DecryptInit_ex failed");

	if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len, (unsigned char *)ctext.c_str(), static_cast<int>(ctext.size())))
		throw std::runtime_error("EVP_DecryptUpdate failed");
	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + len, &len))
		throw std::runtime_error("EVP_DecryptFinal_ex failed");
	plaintext_len += len;
	
	ptext.assign((char *)plaintext.get(), plaintext_len);
}

int CommandServer::Initialize(LogonTouchProvider *pProvider) {
	string path;
	string install_path;

	m_provider = pProvider;

	getLogonTouchRegParam("Config", path);
	getLogonTouchRegParam("", install_path);

	m_config_parser = make_shared<LogonTouchConfigParser>(path);

	auto serverCfgImpl = m_config_parser->parseServerConfig();
	if (serverCfgImpl == nullptr)
		return -1;
	auto serverConfig = make_shared<ServerConfig>(install_path, serverCfgImpl);
	m_server = make_shared<LongonTouchServer>(serverConfig);

	m_server->Server_Assemble([=](const string &key, const string &iv) {
		string decipheredBuf;
		string ciphered_credentials = serverConfig->getClientCredentials();
		auto decodedKey = base64_decode(key);
		auto decodedIV = base64_decode(iv);
		auto decodedCreds = base64_decode(ciphered_credentials);

		unsigned char *iv_buf = (unsigned char *)decodedIV.c_str();
		aes_decrypt((unsigned char *)decodedKey.c_str(), iv_buf, decodedCreds, decipheredBuf);

		auto credential = m_config_parser->parseClientCredentialConfig(decipheredBuf);
		
		return m_provider->OnCredentialsReceived(credential);
	});

	return 0;
}

void CommandServer::ServerStart() {
	if (m_server_thr == nullptr) {
		m_server_thr = make_shared<thread>([this] {
			try { m_server->Server_Start(); }
			catch (...) {
				fprintf(stderr, "Failed to start LogonTouchServer");
			}
		});
		m_server_thr->detach();
	}
}

void CommandServer::ServerStop() {
	m_server->Server_Stop();
	m_server_thr = nullptr;
}

int main( const int, const char** )
{
	string path;
	string install_path;
	
	getLogonTouchRegParam("Config", path);
	getLogonTouchRegParam("", install_path);

	LogonTouchConfigParser configParser(path);

	auto serverCfg = configParser.parseServerConfig();
	auto serverConfig = make_shared<ServerConfig>(install_path, serverCfg);
	auto srv = make_shared<LongonTouchServer>(serverConfig);

	srv->Server_Assemble([=, &configParser] (const string &key, const string &iv){
		string decipheredBuf;
		string ciphered_credentials = serverConfig->getClientCredentials();
		auto decodedKey   = base64_decode(key);
		auto decodedIV = base64_decode(iv);
		auto decodedCreds = base64_decode(ciphered_credentials);

		unsigned char *iv_buf = (unsigned char *)decodedIV.c_str();
		aes_decrypt((unsigned char *)decodedKey.c_str(), iv_buf, decodedCreds, decipheredBuf);

		auto credential = configParser.parseClientCredentialConfig(decipheredBuf);
		return 0;
	});

	srv->Server_Start();


    return EXIT_SUCCESS;
}
