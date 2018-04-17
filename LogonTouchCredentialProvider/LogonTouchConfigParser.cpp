
#include "LogonTouchConfigParser.h"

#include <memory>
#include <cstdlib>
#include <fstream>
#include <iostream>

#include "rapidjson\document.h"     
#include "rapidjson\prettywriter.h" 
#include "rapidjson\istreamwrapper.h"

using namespace rapidjson;
using namespace std;

LogonTouchConfigParser::LogonTouchConfigParser(const string &path) : _config_path(path) {}

shared_ptr<ServerConfigImpl> LogonTouchConfigParser::parseServerConfig() {
	ifstream ifs(_config_path);
	IStreamWrapper isw(ifs);

	_document.ParseStream(isw);
	if (_document.HasParseError()) {
		return nullptr;
	}
	auto serverConfig = make_shared<ServerConfigImpl>();
	if (!_document.HasMember("ServerConfig")) return nullptr;

	Value srvCfg = _document["ServerConfig"].GetObject();

	fillServerConfig(srvCfg, serverConfig);

	return serverConfig;
}

shared_ptr<ClientCredentialImpl> LogonTouchConfigParser::parseClientCredentialConfig(const string &credentials) {

	_document.Parse(credentials.c_str(), credentials.size());
	if (_document.HasParseError()) {
		ParseErrorCode err = _document.GetParseError();
		return nullptr;
	}

	auto credential = make_shared<ClientCredentialImpl>();

	if (_document.HasMember("domain") && _document["domain"].IsString())
		credential->domain = _document["domain"].GetString();

	if (_document.HasMember("username") && _document["username"].IsString())
		credential->username = _document["username"].GetString();

	if (_document.HasMember("password") && _document["password"].IsString())
		credential->password = _document["password"].GetString();

	return credential;
}

void LogonTouchConfigParser::fillServerConfig(Value &srvCfg, shared_ptr<ServerConfigImpl> &config) {
	if (srvCfg.HasMember("version") && srvCfg["version"].IsString())
		config->version = srvCfg["version"].GetString();

	if (srvCfg.HasMember("HTTPPort") && srvCfg["HTTPPort"].IsUint())
		config->http_port = static_cast<uint16_t>(srvCfg["HTTPPort"].GetUint());

	if (srvCfg.HasMember("HTTPSPort") && srvCfg["HTTPSPort"].IsUint())
		config->https_port = static_cast<uint16_t>(srvCfg["HTTPSPort"].GetUint());

	if (srvCfg.HasMember("KeysDir") && srvCfg["KeysDir"].IsObject()) {
		Value keysDir = srvCfg["KeysDir"].GetObject();
		fillKeysDirConfig(keysDir, &config->m_keys_dir);
	}

}

void LogonTouchConfigParser::fillKeysDirConfig(Value &keysDir, KeysDirImpl *config) {
	if (keysDir.HasMember("path") && keysDir["path"].IsString())
		config->path = keysDir["path"].GetString();

	if (keysDir.HasMember("ServerKeysDir") && keysDir["ServerKeysDir"].IsObject()) {
		Value srvKeysDir = keysDir["ServerKeysDir"].GetObject();
		fillServerKeysDir(srvKeysDir, &config->m_server_dir);
	}

	if (keysDir.HasMember("ClientKeysDir") && keysDir["ClientKeysDir"].IsObject()) {
		Value clntKeysDir = keysDir["ClientKeysDir"].GetObject();
		fillClientKeysDir(clntKeysDir, &config->m_client_dir);
	}
}

void LogonTouchConfigParser::fillServerKeysDir(Value &srvKeysDir, ServerKeysDirImpl *config) {
	if (srvKeysDir.HasMember("path") && srvKeysDir["path"].IsString())
		config->path = srvKeysDir["path"].GetString();

	if (srvKeysDir.HasMember("PrivateStore") && srvKeysDir["PrivateStore"].IsString())
		config->privatestore = srvKeysDir["PrivateStore"].GetString();

	if (srvKeysDir.HasMember("PrivatePass") && srvKeysDir["PrivatePass"].IsString())
		config->privatepass = srvKeysDir["PrivatePass"].GetString();

	if (srvKeysDir.HasMember("PublicStore") && srvKeysDir["PublicStore"].IsString())
		config->publicstore = srvKeysDir["PublicStore"].GetString();

	if (srvKeysDir.HasMember("PublicPass") && srvKeysDir["PublicPass"].IsString())
		config->publicpass = srvKeysDir["PublicPass"].GetString();
}

void LogonTouchConfigParser::fillClientKeysDir(Value &clntKeysDir, ClientKeysDirImpl *config) {
	if (clntKeysDir.HasMember("path") && clntKeysDir["path"].IsString())
		config->path = clntKeysDir["path"].GetString();

	if (clntKeysDir.HasMember("PublicStore") && clntKeysDir["PublicStore"].IsString())
		config->publicstore = clntKeysDir["PublicStore"].GetString();

	if (clntKeysDir.HasMember("PublicPass") && clntKeysDir["PublicPass"].IsString())
		config->publicpass = clntKeysDir["PublicPass"].GetString();

	if (clntKeysDir.HasMember("Credentials") && clntKeysDir["Credentials"].IsString())
		config->credentials = clntKeysDir["Credentials"].GetString();
}

const string parseCredentialValue(const string &body, const string &key, const string &default) {
	Document document;

	document.Parse(body.c_str());
	if (document.HasParseError()) {
		return default;
	}

	if (document.HasMember(key.c_str()) && document[key.c_str()].IsString())
		return document[key.c_str()].GetString();

	return default;
}
