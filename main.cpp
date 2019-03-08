#include "b64.h"

using namespace easy_encryption::vigenere::crypt_operations;

int main()
{
	crypt c;
 
	std::string msg = "{\"id\":1,\"method\":\"service.subscribe\",\"params\":[\"myapp/0.1c\", null,\"0.0.0.0\",\"80\"]}";
	std::string key = "THISISMYKEY";
	std::cout << "  message to send: " << msg << std::endl;
	std::string encrypted_msg = c.encrypt(msg, key);
	std::cout << "encrypted message: " << encrypted_msg << std::endl;
	std::string decrypted_msg = c.decrypt(encrypted_msg, key);
	std::cout << "decrypted message: " << decrypted_msg << std::endl;

	std::cin.get();
	return 0;

}
