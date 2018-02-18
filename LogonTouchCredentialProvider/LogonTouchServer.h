#pragma once

#include "ServerConfig.h"
#include <restbed>
#include <memory>

using namespace std;
using namespace restbed;

class LongonTouchServer {
public:

	LongonTouchServer(shared_ptr<ServerConfig> config);

	int Set_Server_Keys_P12(const string &p12_path, const string &p12_pass);
	int Set_Auth_Keys_P12(const string &p12_path, const string &p12_pass);

	void Server_Assemble(const function< int(const string &key, const string &iv) > &on_key_received);

	void Server_Start();
	void Server_Stop();

private:

	typedef struct p12_holder p12_holder_t;
	
	shared_ptr<p12_holder_t> Load_Keys_P12(const string &p12_path, const string &p12_pass);

	Settings      m_settings;
	SSLSettings   m_ssl_settings;
	restbed::Service       m_service;

	const shared_ptr<ServerConfig> m_config = nullptr;
};