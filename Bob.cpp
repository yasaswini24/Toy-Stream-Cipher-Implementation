//Bob's code
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
#include <bits/stdc++.h>
using namespace std;
unsigned char* hashfunc(string&);
int main () {

	// Prepare our context and socket
	zmq::context_t context (2);
	zmq::socket_t socket (context, zmq::socket_type::rep);
	socket.bind ("tcp://*:5555");
	zmq::message_t request;

	// Wait for next request from client
	//receive ciphertext
	zmq::recv_result_t ret = socket.recv (request, zmq::recv_flags::none);
	string rpl = string(static_cast<char*>(request.data()), request.size());
	string cipherrec=rpl;

	
	//receive hash of plain text
	zmq::message_t request2;
	socket.recv (request2, zmq::recv_flags::none);
	string rpl2 = string(static_cast<char*>(request2.data()), request2.size());
	string pt_hash=rpl2;

	

	//Read Key from SharedSecretKey.txt" (32bit)
    	ifstream seed_file("SharedSecretKey.txt");
    	string seed_string((std::istreambuf_iterator<char>(seed_file)),std::istreambuf_iterator<char>());
    	int n_seed=seed_string.length();
    	char seed_array[n_seed+1];
    	strcpy(seed_array,seed_string.c_str());



    	//Generate the key
 	int counter=sizeof(rpl)/8;
 	string key[counter+1];
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
 	}
 
 	
 		
	
	//Decryption
 	unsigned char msg2[rpl.size()];
 	string msg1="";	
	for(int i=0; i <rpl.size(); i++)
	{
		msg2[i] =cipherrec[i] ^ key2[i];
		msg1+=msg2[i];
	}
	
	
	//Put cipher hex into file
	ofstream fout;
	string fname_plain_bob="BobPlaintext.txt";
	fout.open(fname_plain_bob, ios::out);
	fout<<msg1;
	fout.close();
	cout<<"The hash of the ciphertext received is in the file \"BobPlaintext.txt\""<<endl;
	
	// hash the plaintext
    	unsigned char* hashed_pt_msg= hashfunc(msg1);
    	string hash_pt_bob="";
    	stringstream ss;
    	for (int i=0; i<int(sha256_desc.hashsize); i++)
    	{
    		ss << hex << (int)hashed_pt_msg[i];
    		hash_pt_bob= ss.str();
    	}
    	
    	//insert the hash of the plaintext received into the file "Bob_h.txt"
    	string fname_phash_bob="Bob_h.txt";
	fout.open(fname_phash_bob, ios::out);
	fout<<hash_pt_bob;
	fout.close();
    	cout<<"The hash of the plaintext received is in the file \"Bob_h.txt\""<<endl;
    	if(hash_pt_bob==pt_hash) 
    	   cout<< "The plain text is not tampered";
    	else
    	   cout<<"Tampered Data!!!";
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

