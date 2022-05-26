//Alice Code
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <iterator>
#include<fstream>
#include<tomcrypt.h>
#include<iomanip>
using namespace std;
unsigned char* hashfunc(string&);
int main ()
{  
    //Read Message from HW1PlaintextTest.txt
    ifstream msg_file("HW1PlaintextTest.txt");
    string message((istreambuf_iterator<char>(msg_file)),istreambuf_iterator<char>());
    int n_message=message.length();
    //cout<<endl<<sizeof(message)<<endl;
    char message_array[n_message];
    strcpy(message_array,message.c_str());
    
    //The below is to get the count of each character in the plain text file.
    // Please uncomment it if required
    /*for( int j=0;j<n_message;j++)
    	cout<<message_array[j]<<" "<<j<<endl;*/
    	
    if(((n_message)%32)==0){
 
   	//Read Key from SharedSecretKey.txt" (32bit)
   	//cout<<"\n-----SHARED SECRET KEY-----"<<endl;
    	ifstream seed_file("SharedSecretKey.txt");
    	string seed_string((std::istreambuf_iterator<char>(seed_file)),std::istreambuf_iterator<char>());
    	int n_seed=seed_string.length();
    	char seed_array[n_seed+1];
    	strcpy(seed_array,seed_string.c_str());


    	//Hashing the message
    	//cout<<"\n-----HASHED MESSAGE-----"<<endl;
    	unsigned char* hashed_output= hashfunc(message);
    	string hashmsg="";
    	stringstream ss;
    	for (int i=0; i<int(sha256_desc.hashsize); i++)
    	{
    		ss << hex << (int)hashed_output[i];
    		hashmsg= ss.str();
    	}
    	cout<<"This is the hash for the plain text: "<<endl<<hashmsg<<endl<<endl; 
 
 
 	// Generate random Key from seed
 	//cout<<"\n-----HASHED KEY-----"<<endl;
 	int counter=n_message/32;
 	string key2="";
 	stringstream ss1;
 	for(int j=1;j<=counter;j++){
 		string input_to_sha=seed_string+to_string(j);
		string hash="";
 		unsigned char* hashed_for_key= hashfunc(input_to_sha);
    		for (int i=0; i<int(sha256_desc.hashsize); i++)
    		{
    		ss1 << hex << (int)hashed_for_key[i];
    		hash = ss1.str();
    		}
    		key2+=hash;
    		hash="";
 	}
 	

 	
 	//generate cipher text
 	//cout<<"\n ----- Cipher Text -----\n";
 	char ciphertxt[n_message];
 	stringstream c_ss;
 	int cipherpointer=0;
 	string str_c="";
	for(int i = 0; i < n_message; i++)
		{
		ciphertxt[cipherpointer] = message_array[i]^key2[i];
		c_ss<<hex<<(int)ciphertxt[i];
		str_c+=ciphertxt[cipherpointer];
		cipherpointer=cipherpointer+1;
		}
	string cipher_hex=c_ss.str();
	
	
	
	//Put cipher hex into file
	ofstream fout;
	string fname_ciphertext="TheCiphertext.txt";
	fout.open(fname_ciphertext, ios::out);
	fout<<cipher_hex;
	fout.close();	
	cout<<"You can find the hex of cipher key in the file named \"TheCiphertext.txt\""<<endl;

		
	// ------ ZeroMQ ------

	// Prepare our context and socket
	zmq::context_t context (1);
	zmq::socket_t socket (context, zmq::socket_type::req);
	cout << "Connecting to server..." << std::endl;
	socket.connect ("tcp://localhost:5555");

	// Send the request
	zmq::message_t request (str_c.size());
	memcpy (request.data(), str_c.data(), str_c.size());
	cout << "Sending Message ..." << std::endl;
	socket.send(request, ZMQ_SNDMORE);
	zmq::message_t request2(hashmsg.size());
	memcpy(request2.data(), hashmsg.data(), hashmsg.size());
	socket.send(request2, zmq::send_flags::none);
    }
    else{
    	cout<<"Sorry! Your input file length must be a multiple of 32";
    }
    	return 0;
}

unsigned char* hashfunc(string& msg){
	unsigned char* hash_out = new unsigned char[sha256_desc.hashsize];
	hash_state md;
	sha256_init(&md);
	sha256_process(&md,(unsigned char*)msg.c_str(),msg.size());
	sha256_done(&md,hash_out);
	return hash_out;
}

