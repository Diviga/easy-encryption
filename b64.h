#pragma once
#include <string>
#include <sstream>
#include <iostream>
#include <vector>

namespace easy_encryption {

	class b64 {
	private:
		std::string enc_out;
		std::string dec_out;

	protected:
		std::string base64_encode(const std::string &in);
		std::string base64_decode(const std::string &in);

	public:
	};

	inline std::string b64::base64_encode(const std::string &in) {
		int val = 0, valb = -6;
		for (int jj = 0; jj < in.size(); jj++) {
			char c = in[jj];
			val = (val << 8) + c;
			valb += 8;
			while (valb >= 0) {
				enc_out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
				valb -= 6;
			}
		}
		if (valb > -6) enc_out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
		while (enc_out.size() % 4) enc_out.push_back('=');
		return enc_out;
	}

	inline std::string b64::base64_decode(const std::string &in){
		std::vector<int> T(256, -1);
		for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

		int val = 0, valb = -8;
		for (int jj = 0; jj < in.size(); jj++) {
			char c = in[jj];
			if (T[c] == -1) break;
			val = (val << 6) + T[c];
			valb += 6;
			if (valb >= 0) {
				dec_out.push_back(char((val >> valb) & 0xFF));
				valb -= 8;
			}
		}
		return dec_out;
	}


	namespace vigenere {

		class vigenere{
		private:
			// variables
			std::string AVAILABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";

			// functions
			int index(char c);
		protected:
			std::string extend_key(std::string& msg, std::string& key);
			std::string encrypt_vigenere(std::string& msg, std::string& key);
			std::string decrypt_vigenere(std::string& encryptedMsg, std::string& newKey);
		};

		inline int vigenere::index(char c) {
			for (int ii = 0; ii < AVAILABLE_CHARS.size(); ii++) {
				if (AVAILABLE_CHARS[ii] == c) {
					return ii;
				}
			}
			return -1;
		}

		inline std::string vigenere::extend_key(std::string& msg, std::string& key) {
			//generating new key
			int msgLen = msg.size();
			std::string newKey(msgLen, 'x');
			int keyLen = key.size(), i, j;
			for (i = 0, j = 0; i < msgLen; ++i, ++j) {
				if (j == keyLen)
					j = 0;
				newKey[i] = key[j];
			}
			newKey[i] = '\0';
			return newKey;
		}

		inline std::string vigenere::encrypt_vigenere(std::string& msg, std::string& key) {
			int msgLen = msg.size(), keyLen = key.size(), i, j;
			std::string encryptedMsg(msgLen, 'x');
			std::string newKey = extend_key(msg, key);

			for (i = 0; i < msgLen; ++i) {
				if (isalnum(msg[i]) or msg[i] == ' ') {
					encryptedMsg[i] = AVAILABLE_CHARS[((index(msg[i]) + index(newKey[i])) % AVAILABLE_CHARS.size())];
				}
				else {
					encryptedMsg[i] = msg[i];
				}
			}
			encryptedMsg[i] = '\0';
			return encryptedMsg;
		}

		inline std::string vigenere::decrypt_vigenere(std::string& encryptedMsg, std::string& newKey) {

			int msgLen = encryptedMsg.size();
			std::string decryptedMsg(msgLen, 'x');
			int i;
			for (i = 0; i < msgLen; ++i) {
				if (isalnum(encryptedMsg[i]) or encryptedMsg[i] == ' ') {
					decryptedMsg[i] = AVAILABLE_CHARS[(((index(encryptedMsg[i]) - index(newKey[i])) + AVAILABLE_CHARS.size()) % AVAILABLE_CHARS.size())];
				}
				else {
					decryptedMsg[i] = encryptedMsg[i];
				}
			}
			decryptedMsg[i] = '\0';
			return decryptedMsg;
		}


		namespace crypt_operations {

			class crypt : protected b64, protected vigenere{
			public:
				std::string encrypt(std::string& msg, std::string& key);
				std::string decrypt(std::string& encrypted_msg, std::string& key);
			private:

			};

			inline std::string crypt::encrypt(std::string& msg, std::string& key) {
				std::string b64_str = base64_encode(msg);
				std::string vigenere_msg = encrypt_vigenere(b64_str, key);
				return vigenere_msg;
			}


			inline std::string crypt::decrypt(std::string& encrypted_msg, std::string& key) {
				std::string newKey = extend_key(encrypted_msg, key);
				std::string b64_encoded_str = decrypt_vigenere(encrypted_msg, newKey);
				std::string b64_decode_str = base64_decode(b64_encoded_str);
				return b64_decode_str;
			}


		} // crypt_operations
	} // vigenere
} // easy_encryption