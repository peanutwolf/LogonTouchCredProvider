

#include "ServerConfig.h"
#include <fstream>
#include <iostream>

string path_append(const string &path) {
	string path_tmp = path;
	if (path_tmp.length() > 0) {
		path_tmp.insert(path_tmp.begin(), pseparator());
	}
	return path_tmp;
}

ServerConfig::ServerConfig(const string &install_path, shared_ptr<ServerConfigImpl> impl) : install_path(install_path), m_pimpl(impl) {}

uint16_t ServerConfig::getHTTPPort() {
	return m_pimpl->http_port;
}

uint16_t ServerConfig::getHTTPSPort() {
	return m_pimpl->https_port;
}

const string ServerConfig::getServerPrivateStorePath() {
	return install_path
		+ path_append(m_pimpl->m_keys_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_server_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_server_dir.privatestore);
}

const string ServerConfig::getServerPrivatePassPath() {
	return install_path
		+ path_append(m_pimpl->m_keys_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_server_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_server_dir.privatepass);
}

const string ServerConfig::getClientPublicStorePath() {
	return install_path
		+ path_append(m_pimpl->m_keys_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.publicstore);
}

const string ServerConfig::getClientPublicPassPath() {
	return install_path
		+ path_append(m_pimpl->m_keys_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.publicpass);
}

const string ServerConfig::getClientCredentialsPath() {
	return install_path
		+ path_append(m_pimpl->m_keys_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.path)
		+ path_append(m_pimpl->m_keys_dir.m_client_dir.credentials);
}

const string ServerConfig::getServerPrivatePass() {
	string pass_tmp;
	ifstream passfile_stream(getServerPrivatePassPath());
	getline(passfile_stream, pass_tmp);

	return pass_tmp;
}

const string ServerConfig::getClientPublicPass() {
	string pass_tmp;
	ifstream passfile_stream(getClientPublicPassPath());
	getline(passfile_stream, pass_tmp);

	return pass_tmp;
}

const string ServerConfig::getClientCredentials() {
	string cred_tmp;
	ifstream credfile_stream(getClientCredentialsPath());
	getline(credfile_stream, cred_tmp);

	return cred_tmp;
}
