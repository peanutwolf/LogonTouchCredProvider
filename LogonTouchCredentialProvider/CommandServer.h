#pragma once

#include "LogonTouchProvider.h"
#include "LogonTouchConfigParser.h"
#include "LogonTouchServer.h"

#include <memory>
#include <thread> 

class LogonTouchProvider;

class CommandServer {
public:
	int Initialize(LogonTouchProvider *pProvider);

	void ServerStart();
	void ServerStop();
private:

	LogonTouchProvider *m_provider = NULL;

	shared_ptr<LogonTouchConfigParser> m_config_parser;
	shared_ptr<LongonTouchServer> m_server;

	shared_ptr<thread> m_server_thr;
};