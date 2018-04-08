#include "LogonTouchServer.h"
#include "LogonTouchConfigParser.h"
#include "ServerConfig.h"
#include <memory>
#include <functional>
#include <cstdlib>
#include <restbed>
#include <openssl\bio.h>
#include <openssl\pkcs12.h>
#include <openssl\pem.h>
#include <openssl\err.h>


using namespace std;
using namespace restbed;

class SecureRedirectRule : public Rule {
public:
	SecureRedirectRule(const uint16_t http_port, const uint16_t secure_port) :
		Rule(), _http_port(http_port), _secure_port(secure_port) {}

	virtual void action(const std::shared_ptr< Session > session, const std::function< void(const std::shared_ptr< Session >) >& callback) {
		auto destination = session->get_destination();
		uint16_t port = parse_port(destination);

		if (port == _http_port) {
			auto redirect_url = string("https://");
			auto path = session->get_request()->get_path();
			auto query = session->get_request()->get_query_parameters();

			redirect_url += parse_ip(destination) + ":" + to_string(_secure_port);

			if (not path.empty()) {
				redirect_url += path;
			}
			if (not query.empty()) {
				for (multimap<string, string>::iterator it = query.begin(); it != query.end(); it++) {
					redirect_url += it == query.begin() ? "?" : "&&";
					redirect_url += it->first + '=' + it->second;
				}
			}
			session->close(FOUND,
				{ { "Content-Length", "0" },{ "Location", redirect_url.c_str() } });

		}
		else {
			callback(session);
		}
	}

private:
	uint16_t parse_port(const string &ip_addr) {
		size_t pos = ip_addr.find_last_of(':');
		if (pos == string::npos)
			return 0;
		auto port_str = ip_addr.substr(pos + 1);
		return static_cast<uint16_t>(stoi(port_str));
	}

	string parse_ip(const string &ip_addr) {
		size_t pos = ip_addr.find_last_of(':');
		if (pos == string::npos)
			return "[::]";
		return ip_addr.substr(0, pos);
	}

	uint16_t _http_port;
	uint16_t _secure_port;
};

class CustomLogger : public Logger
{
public:

	CustomLogger() {
		_logger = spdlog::get("logger");
	}

	void stop(void)
	{
		return;
	}

	void start(const shared_ptr< const Settings >&)
	{
		return;
	}

	void log(const Level, const char* format, ...)
	{
		va_list arguments;
		va_start(arguments, format);
		char buf[10000] = { 0 };

		vsnprintf(buf, sizeof buf, format, arguments);

		_logger->debug("{}", buf);

		va_end(arguments);
	}

	void log_if(bool expression, const Level level, const char* format, ...)
	{
		if (expression)
		{
			va_list arguments;
			va_start(arguments, format);
			log(level, format, arguments);
			va_end(arguments);
		}
	}

private:
	shared_ptr<spdlog::logger> _logger = nullptr;
};


typedef struct p12_holder {
	~p12_holder() {
		if (pkey != NULL) EVP_PKEY_free(pkey);
		if (cert != NULL) X509_free(cert);
		if (ca != NULL)   sk_X509_pop_free(ca, X509_free);
	}

	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
}p12_holder_t;

LongonTouchServer::LongonTouchServer(shared_ptr<ServerConfig> config) : m_config(config) {
	_logger = spdlog::get("logger");
}

int LongonTouchServer::Set_Server_Keys_P12(const string &p12_path, const string &p12_pass) {
	auto p12_holder = Load_Keys_P12(p12_path, p12_pass);

	if (p12_holder->pkey) {
		unsigned char *pkey_buf = NULL;
		int key_size = i2d_PrivateKey(p12_holder->pkey, &pkey_buf);
		m_ssl_settings.set_private_key(pkey_buf, key_size);
	}

	if (p12_holder->cert) {
		unsigned char *cert_buf = NULL;
		int cert_size = i2d_X509(p12_holder->cert, &cert_buf);
		m_ssl_settings.set_certificate(cert_buf, cert_size);
	}

	return 1;
}

int LongonTouchServer::Set_Auth_Keys_P12(const string &p12_path, const string &p12_pass) {
	auto p12_holder = Load_Keys_P12(p12_path, p12_pass);
	auto bio_mem = shared_ptr<BIO>(BIO_new(BIO_s_mem()), BIO_free);

	if (!PEM_write_bio_X509(bio_mem.get(), sk_X509_pop(p12_holder->ca))) {
		_logger->error("[Set_Auth_Keys_P12] Failed to convert PEM cert to X509 format");
		return -1;
	}

	unsigned char *ca_cert_buf = NULL;
	int ca_cert_size = BIO_get_mem_data(bio_mem.get(), &ca_cert_buf);

	m_ssl_settings.set_client_authentication_enabled(true);
	m_ssl_settings.set_ca_certificate(ca_cert_buf, ca_cert_size);

	return 1;
}

void LongonTouchServer::credential_provider_handler(const shared_ptr< Session > session, const function< int(const string &key, const string &iv) >& on_key_received) {
	const auto request = session->get_request();

	if (request->has_header("Content-Length")){
		int length = request->get_header("Content-Length", 0);

		session->fetch(length, [=](const shared_ptr< Session > session, const Bytes&){
			const auto request = session->get_request();
			const auto body = request->get_body();

			auto req_body = string(reinterpret_cast<const char *>(body.data()), body.size());
			auto key = parseCredentialValue(req_body, "key");
			auto iv = parseCredentialValue(req_body, "iv");

			if (key.empty()) _logger->error("Failed to parse credential value=[key]");
			if (iv.empty()) _logger->error("Failed to parse credential value=[iv]");

			if (on_key_received(key, iv) == 0) {
				session->close(OK);
			}else {
				session->close(EXPECTATION_FAILED);
			}
			
		});
	}else{
		_logger->error("Received request without content-length header");
		session->close(BAD_REQUEST);
	}	
}

void LongonTouchServer::Server_Assemble(const function< int(const string &key, const string &iv) >& on_key_received) {
	using namespace std::placeholders;
	const function< void(const shared_ptr< Session >) > handler 
		= std::bind(&LongonTouchServer::credential_provider_handler, this,  _1, on_key_received);

	auto resource = make_shared< Resource >();
	resource->set_path("external/credential/provide");
	resource->add_rule(make_shared<SecureRedirectRule>(m_config->getHTTPPort(), m_config->getHTTPSPort()));
	resource->set_method_handler("POST", handler);

	Set_Server_Keys_P12(m_config->getServerPrivateStorePath(), m_config->getServerPrivatePass());
	Set_Auth_Keys_P12(m_config->getClientPublicStorePath(), m_config->getClientPublicPass());

	m_ssl_settings.set_http_disabled(false);
	m_ssl_settings.set_port(m_config->getHTTPSPort());
	//m_ssl_settings.set_temporary_diffie_hellman(Uri("file://dh2048.pem"));

	m_settings.set_port(m_config->getHTTPPort());
	m_settings.set_ssl_settings(shared_ptr<SSLSettings>(&m_ssl_settings));

	m_service.publish(resource);
	m_service.set_logger(make_shared< CustomLogger >());
}

void LongonTouchServer::Server_Start() {
	m_service.start(shared_ptr<Settings>(&m_settings));
}

void LongonTouchServer::Server_Stop() {
	m_service.stop();
}

shared_ptr<p12_holder_t> LongonTouchServer::Load_Keys_P12(const string &p12_path, const string &p12_pass) {
	auto holder = make_shared<p12_holder_t>();

	auto p12_bio = shared_ptr<BIO>(BIO_new_file(p12_path.c_str(), "r"), BIO_free);
	if (p12_bio == nullptr) { 
		_logger->error("Failed to load p12 file path=[{}]", p12_path);
		return nullptr;
	}

	auto p12_cert = shared_ptr<PKCS12>(d2i_PKCS12_bio(p12_bio.get(), NULL), PKCS12_free);
	if (p12_cert == nullptr) {
		_logger->error("Failed to read p12 cert path=[{}]", p12_path);
		return nullptr;
	}

	int res = PKCS12_parse(p12_cert.get(), p12_pass.c_str(), &holder->pkey, &holder->cert, &holder->ca);
	_logger->debug("PKCS12 certificates parse result=[{}]", res);

	return holder;
}

