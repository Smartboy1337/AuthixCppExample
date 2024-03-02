#include "main.hpp"

int main()
{
	std::string InitSessionResponse = Authix::InitSession();

	bool InitSessionSuccess;
	std::string InitSessionData;
	try
	{
		json jsonData = json::parse(InitSessionResponse);

		InitSessionSuccess = jsonData["success"];
		InitSessionData = jsonData["data"];

		std::cout << "InitSessionSuccess: " << std::boolalpha << InitSessionSuccess << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cout << "nError during the JSON parsing: " << e.what() << std::endl;
	}

	std::string InitSessionDecryptedData = Authix::DecryptInitData(InitSessionData);

	std::string SessionID;
	int Expires;
	std::string NewIV;
	try 
	{
		json jsonData = json::parse(InitSessionDecryptedData);

		SessionID = jsonData["session_id"];
		std::cout << "\nSession_id: " << SessionID << std::endl;
		Expires = jsonData["expires_at"];
		std::cout << "Expires: " << Expires << std::endl;
		NewIV = jsonData["iv"];
		std::cout << "New_iv: " << NewIV << std::endl;
	}
	catch (const std::exception& e) 
	{
		std::cout << "nError during the JSON parsing: " << e.what() << std::endl;
	}

	std::string License;
	std::cout << "\nYour License --> ";
	std::cin >> License;
	std::cout << "\n";

	std::string UserHwid = GrabSID();
	std::string LoginResponse = Authix::Login(License, UserHwid, SessionID);
	//std::cout << "\nLoginResponse: " << LoginResponse << std::endl;

	bool LoginSuccess;
	std::string LoginData;
	std::string LoginMessage;
	json jsonData = json::parse(LoginResponse);

	LoginSuccess = jsonData["success"];
	if (!LoginSuccess)
	{
		LoginMessage = jsonData["message"];
		std::cout << "LoginSuccess: " << std::boolalpha << LoginSuccess << std::endl;
		std::cout << "LoginMessage: " << LoginMessage << std::endl;
	}
	else
	{
		LoginData = jsonData["data"];
		std::cout << "LoginSuccess: " << std::boolalpha << LoginSuccess << std::endl;
	}

	if (!LoginSuccess) 
	{
		Sleep(2000);
		return 1;
	}

	std::string LoginDecryptedData = Authix::DecryptLoginData(LoginData, NewIV);
	//std::cout << "\nLoginDecryptedData: " << LoginDecryptedData << std::endl;

	int LicenseExpiry;
	try
	{
		json jsonData = json::parse(LoginDecryptedData);

		LicenseExpiry = jsonData["expires_at"];

		std::cout << "LicenseExpiry: " << LicenseExpiry << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cout << "\nError during the JSON parsing: " << e.what() << std::endl;
	}

	std::cout << "\nSuccessfully Logged in!" << std::endl;

	Sleep(-1);

	return 0;
}