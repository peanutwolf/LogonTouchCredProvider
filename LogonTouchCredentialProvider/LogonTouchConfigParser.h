#pragma once


#include "ServerConfig.h"

#include <memory>
#include <cstdlib>

#include "rapidjson\document.h"     
#include "rapidjson\prettywriter.h" 
#include "rapidjson\istreamwrapper.h"

using namespace rapidjson;
using namespace std;


class LogonTouchConfigParser {
public:
	LogonTouchConfigParser(const string &path);

	shared_ptr<ServerConfigImpl> parseServerConfig();

	shared_ptr<ClientCredentialImpl> parseClientCredentialConfig(const string &credentials);
private:
	void fillServerConfig(Value &srvCfg, shared_ptr<ServerConfigImpl> &config);
	void fillKeysDirConfig(Value &keysDir, KeysDirImpl *config);
	void fillServerKeysDir(Value &srvKeysDir, ServerKeysDirImpl *config);
	void fillClientKeysDir(Value &clntKeysDir, ClientKeysDirImpl *config);

	string   _config_path = "";
	Document _document;
};

const string parseCredentialValue(const string &body, const string &key, const string &default = "");