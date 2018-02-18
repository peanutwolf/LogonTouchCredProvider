#pragma once

#include <string>
#include <memory>

using namespace std;

static inline const char pseparator() {
#if defined(WIN32) || defined(_WIN32)
	return '\\';
#else
	return '/';
#endif
}

string path_append(const string &path);

struct ServerKeysDirImpl {
	string path = "";
	string publicstore = "publicstore.pkcs12";
	string publicpass = "publicstore.key";
	string privatestore = "privatestore.pkcs12";
	string privatepass = "publicstore.key";
};

struct ClientKeysDirImpl {
	string path = "";
	string publicstore = "publicstore.pkcs12";
	string publicpass = "publicstore.key";
	string credentials = "credentials.cip";
};

struct KeysDirImpl {
	string path = "";
	ServerKeysDirImpl m_server_dir;
	ClientKeysDirImpl m_client_dir;
};

struct ServerConfigImpl {
	string version = "0.0";
	uint16_t http_port = 8080;
	uint16_t https_port = 7779;
	KeysDirImpl m_keys_dir;
};

struct ClientCredentialImpl {
	string domain = "";
	string username = "";
	string password = "";
};

class ServerConfig {
public:
	ServerConfig(const string &install_path, shared_ptr<ServerConfigImpl> impl);

	uint16_t getHTTPPort();
	uint16_t getHTTPSPort();

	const string getServerPrivateStorePath();
	const string getServerPrivatePassPath();
	const string getClientPublicStorePath();
	const string getClientPublicPassPath();
	const string getClientCredentialsPath();

	const string getServerPrivatePass();
	const string getClientPublicPass();
	const string getClientCredentials();
private:
	shared_ptr<ServerConfigImpl> m_pimpl = make_shared<ServerConfigImpl>();
	string install_path = "";
};
