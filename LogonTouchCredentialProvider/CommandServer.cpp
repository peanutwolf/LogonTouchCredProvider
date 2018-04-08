
#include "CommandServer.h"
#include "ServerConfig.h"
#include "Base64.h"

#include <memory>
#include <cstdlib>
#include <asio\buffer.hpp>
#include <Windows.h>
#include <Winreg.h>
#include <thread>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

void server_thread(LongonTouchServer *server) {
	server->Server_Start();
}

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

CommandServer::CommandServer() {
	_logger = spdlog::get("logger");
}

int CommandServer::Initialize(LogonTouchProvider *pProvider) {
	string path;
	string install_path;

	m_provider = pProvider;

	logontouch::getLogonTouchRegParam("Config", path);
	logontouch::getLogonTouchRegParam("", install_path);

	_logger->debug("Try parse LogonTouch config for path=[{}]", path.c_str());
	
	m_config_parser = make_shared<LogonTouchConfigParser>(path);

	auto serverCfgImpl = m_config_parser->parseServerConfig();
	if (serverCfgImpl == nullptr) {
		_logger->error("Failed to parse LogonTouch server config");
		return -1;
	}
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
		if (credential == nullptr) _logger->error("Failed to parse deciphered client credentials");
		
		return m_provider->OnCredentialsReceived(credential);
	});

	_logger->info("CommandServer initialized successfully");

	return 0;
}

void CommandServer::ServerStart() {
	if (m_server_thr == nullptr) {
		m_server_thr = make_shared<thread>([this] {
			auto logger = spdlog::get("logger");
			try { m_server->Server_Start(); }
			catch (const std::runtime_error& re){
				logger->error("Runtime error occurred while starting LogonTouchServer {}", re.what());
			}
			catch (const std::exception& ex){
				logger->error("Error occurred while starting LogonTouchServer {}", ex.what());
			}
			catch (...) {
				logger->error("Unknown exception caught while starting LogonTouchServer");
			}
		});
		m_server_thr->detach();
	}
}

void CommandServer::ServerStop() {
	m_server->Server_Stop();
	m_server_thr = nullptr;
}

//main method for exe file 

//int main( const int, const char** )
//{
//	string path;
//	string install_path;
//	
//	logontouch::getLogonTouchRegParam("Config", path);
//	logontouch::getLogonTouchRegParam("", install_path);
//
//	LogonTouchConfigParser configParser(path);
//
//	auto serverCfg = configParser.parseServerConfig();
//	auto serverConfig = make_shared<ServerConfig>(install_path, serverCfg);
//	auto srv = make_shared<LongonTouchServer>(serverConfig);
//
//	srv->Server_Assemble([=, &configParser] (const string &key, const string &iv){
//		string decipheredBuf;
//		string ciphered_credentials = serverConfig->getClientCredentials();
//		auto decodedKey   = base64_decode(key);
//		auto decodedIV = base64_decode(iv);
//		auto decodedCreds = base64_decode(ciphered_credentials);
//
//		unsigned char *iv_buf = (unsigned char *)decodedIV.c_str();
//		aes_decrypt((unsigned char *)decodedKey.c_str(), iv_buf, decodedCreds, decipheredBuf);
//
//		auto credential = configParser.parseClientCredentialConfig(decipheredBuf);
//		return 0;
//	});
//
//	srv->Server_Start();
//
//
//    return EXIT_SUCCESS;
//}
