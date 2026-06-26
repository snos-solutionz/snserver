#include "SnServer.h"

int main() {
	SnServer server(8000);

	server.add_route("GET", "/hello", [](const Request& rq) {
		HeaderMap hdrs;
		Response res(200, hdrs, "hello");
		return res;
	});

	server.add_route("GET", "/user_agent", [](const Request& rq) {
		HeaderMap hdrs;
		std::string resstr = "Your User-Agent is: " + rq.headers["User-Agent"];
		Response res(200, hdrs,  resstr);
		return res;
	});

	server.add_route("GET", "/headers", [](const Request& rq) {
		HeaderMap hdrs, rqHdrs = rq.headers;
		std::string resstr = "Your headers are: " + rqHdrs.to_string();
		Response res(200, hdrs,  resstr);
		return res;
	});

	server.add_route("GET", "/hello_wide", [](const Request& rq) {
		HeaderMap hdrs;
		hdrs["Content-Type"] = "text/html; charset=UTF-16";
		Response res(200, hdrs, L"<h1>helloö</h1>");
		return res;
	});

	server.add_route("POST", "/body", [](const Request& rq) {
		HeaderMap hdrs;
		std::string resstr = std::string((LPCSTR)rq.body.data(), rq.body.size());
		Response res(200, hdrs, resstr);
		return res;
	});

#ifdef _USE_TLS
	server.LoadPfx(PFX_FILE, PFX_PASSWORD);
#endif

	server.staticPath = STATIC_PATH;
	server.start();

	return 0;
}