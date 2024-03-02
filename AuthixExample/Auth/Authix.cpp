#include "Authix.hpp"
#include "Decryption.hpp"

std::string PanelURL = "https://example.authix.win/";
std::string OwnerUUID = "00000000-0000-0000-0000-0000000000000"; // you can find OwnerUUID in your dashboard
std::string AppName = "example";
std::string AppSecretKey = "0000000000000000000000000000000000000000000000000000000000000000";

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output)
{
	size_t total_size = size * nmemb;
	output->append((char*)contents, total_size);

	return total_size;
}

namespace Authix
{
	std::string InitSession()
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		auto link = std::format("{}api/start", PanelURL);
		curl_easy_setopt(hnd, CURLOPT_URL, link.c_str());

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, "accept: application/json");
		headers = curl_slist_append(headers, "content-type: application/json");
		headers = curl_slist_append(headers, "User-Agent: AuthixExample");
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		Decryption::init_iv();

		auto command = std::format("{{\"owner_uuid\":\"{}\",\"application\":\"{}\",\"init_iv\":\"{}\"}}", OwnerUUID, AppName, ivKey);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);
		
		return response_string;
	}
	std::string DecryptInitData(std::string Data)
	{
		std::string DecryptedData = Decryption::InitialDecryptData(Data, AppSecretKey);

		return DecryptedData;
	}

	std::string Login(std::string License, std::string Hwid, std::string SessionID)
	{
		CURL* hnd = curl_easy_init();
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
		auto link = std::format("{}api/login", PanelURL);
		curl_easy_setopt(hnd, CURLOPT_URL, link.c_str());

		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, "accept: application/json");
		headers = curl_slist_append(headers, ("x-session-id: " + SessionID).c_str());
		headers = curl_slist_append(headers, "content-type: application/json");
		headers = curl_slist_append(headers, "User-Agent: BadwarePaidSpafer");
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

		std::string response_string;
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);

		auto command = std::format("{{\"license_key\":\"{}\",\"hwid\":\"{}\"}}", License, Hwid);
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, command.c_str());
		curl_easy_perform(hnd);

		//std::cout << "\nlogin response:" << response_string << std::endl;
		return response_string;
	}
	std::string DecryptLoginData(std::string Data, std::string NewIV)
	{
		std::string DecryptedData = Decryption::DecryptData(Data, AppSecretKey, NewIV);

		return DecryptedData;
	}
}