//////////////////////////////////////////////////////////////
// TCP SECURE SERVER GCC (IPV6 ready)
//
//
// References: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520(v=vs.85).aspx
//             http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html#daytimeServer6
//
//////////////////////////////////////////////////////////////

#define DEFAULT_PORT "1234"
#define USE_IPV6 true // if set to false, IPv4 addressing scheme will be used; you need to set this to true to
                      // enable IPv6 later on.  The assignment will be marked using IPv6!

#if defined __unix__ || defined __APPLE__
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h> //used by getnameinfo()
#include <iostream>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/math/constants/constants.hpp>

using namespace boost::multiprecision;

#elif defined __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h> //required by getaddrinfo() and special constants
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/math/constants/constants.hpp>

using namespace boost::multiprecision;

#define WSVERS MAKEWORD(2, 2) /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
// The high-order byte specifies the minor version number;
// the low-order byte specifies the major version number.
WSADATA wsadata; // Create a WSADATA object called wsadata.
#endif

#define BUFFER_SIZE 500
#define RBUFFER_SIZE 256

using namespace std;

///////////////////////////////////////////////////////////////////////

/////////////////NOTES////////////
/*
Week 6
Server
- Has a pubic key (e,n) and a private key (d,n)
- Has a cert issued by a CA dCA(e,n) <- encrypted public key of the server
make our own dCA(e,n)

CLIENT
- eCA RSA public key
- nonce - used as part of CBC

Exchange
1. SERVER - Send cert dCA(e,n) to client
2. Client- extracts the public key of the server (e,n) usding its CA public key eCA(dCA(e,n)) -> (e,n)
3. Client - Send "ACK 226 Public key received"
4. Client - Send e(nonce)
5. Server - Extract nonce using its private key (d,n) -> Sed "ACK 220 nonce ok"
6. CLIEN - Each message from client is then encrypted using the RSA-CBC and server decrypts boom.


*/
/////////////////////////////////////////////////////////////////////

// Repeat_square y = x^e mod n

unsigned long long repeat_square(unsigned long long x, unsigned long long e, unsigned long long n)
{
   unsigned long long int y = 1; // initialize y to 1, very important
   while (e > 0)
   {
      if ((e % 2) == 0) // If exponent is even
      {
         x = (x * x) % n; // Square x and take modulo
         e = e / 2;       // Divide exponent by 2
      }
      else // If exponent is odd
      {
         y = (x * y) % n; // Multiply result by current x value and take modulo
         e = e - 1;       // Decrease exponent by 1
      }
   }
   return y;
}
// KEYS and CERT//

// Structure to hold the public key and private key
struct RSA
{
   unsigned long long e; // Public
   unsigned long long n; // Modulus
   unsigned long long d; // Private
};

struct CA
{
   unsigned long long eCA; // CA's public
   unsigned long long nCA; // CA's modulus
   unsigned long long dCA; // CA's private
};

// Here we can Gen the RSA keys for the server
//  This sets up the public key (e,n) and private key (d,n) as discussed in Week_05 lectures and based on Week 6 Part 3
void generateRSA(RSA *serverKey)
{
   // Using the example values from lecture Week_06_Network_Security_Part_3
   unsigned long long p = 173; // First prime number
   unsigned long long q = 149; // Second prime number

   serverKey->n = p * q;                     // 25777;   // n = p*q, public modulus
   unsigned long long z = (p - 1) * (q - 1); // z = (p-1)(q-1) = 25456
   serverKey->e = 3;                         // Public exponent (must be coprime with z)
   serverKey->d = 16971;                     // Private exponent (calculated such that ed ≡ 1 (mod z))

   // KEYS
   // public(e,n)
   //  e = 3; //public
   //  n = 25777; //public
   // private(d,n)
   //  d = 16971; // private
   //  n = 25777; //private
}

// Generate the CA keys (similar to RSA keys but for the Certificate Authority)
void generateCA(CA *caCert)
{ // TODO: CHANGE VALUES FOR CA
   // Currently using the same values as server keys
   // In a real system, CA would use larger primes for added security
   unsigned long long p = 173;
   unsigned long long q = 149;

   caCert->nCA = p * q;                      // 25777;
   unsigned long long z = (p - 1) * (q - 1); // 25456
   caCert->eCA = 3;                          // CA's public exponent
   caCert->dCA = 16971;                      // CA's private exponent
}

// Create a certificate for the server by signing its public key with CA's private key
// This implements the certificate creation process described in Week_06_Network_Security_part_4
unsigned long long CreateCert(RSA *serverKey, CA *caCert)
{
   // In a real system, would include more certificate data
   // Here we're simplifying by just signing the exponent e
   unsigned long long together = serverKey->e;
   return repeat_square(together, caCert->dCA, caCert->nCA); // Sign using CA's private key
}

// Verify a certificate using the CA's public key
// Client uses this to extract the server's authentic public key
unsigned long long verifyCert(unsigned long long &cert, CA *caCert)
{
   // Verify the certificate by decrypting with CA's public key
   return repeat_square(cert, caCert->eCA, caCert->nCA);
}
// Display key information using pointers
void displayServerKeys(RSA *keys)
{
   cout << "\n=====================SERVER KEYS=======================" << endl;
   cout << "Server's Public Key (e,n): (" << keys->e << ", " << keys->n << ")" << endl;
   cout << "Server's Private Key (d,n): (" << keys->d << ", " << keys->n << ")" << endl;
   cout << "\n=======================================================" << endl;
}

// Display certificate information using pointers
void displayCertificate(unsigned long long cert, CA *caCert)
{
   cout << "\n======================CERT KEYS=========================" << endl;
   cout << "Certificate dCA(e,n): " << cert << endl;
   cout << "Certificate signed with CA keys (dCA,nCA): (" << caCert->dCA << ", " << caCert->nCA << ")" << endl;
   cout << "\n=======================================================" << endl;
}
// TestFucntion
void testRSA_4()
{
   cout << "<< RSA TEST >>" << endl;
   cout << "integer numbers." << endl;
   unsigned long long e, n, z;
   unsigned long long d;
   // int nonce;
   // int calculatedRandomNum;
   // p=173 and q=149
   // int p=173;
   // int q=149;

   // note: p and q must be prime numbers!
   //  int p=5;
   //  int q=7;

   // n=p*q;
   // z = (p-1)*(q-1);
   // e = 5;
   // d = 29;
   // int input = 12;

   //------------------------
   // lecture
   int p = 173;
   int q = 149;

   n = 25777;
   z = (p - 1) * (q - 1); // 25456
   e = 3;                 // public
   d = 16971;             // private

   // KEYS

   // public(e,n)
   //  e = 3; //public
   //  n = 25777; //public
   // private(d,n)
   //  d = 16971; // private
   //  n = 25777; //private

   //------------------------

   // //lecture
   // unsigned long long p=431;
   // unsigned long long q=443;

   // n=190933;
   // z = (p-1)*(q-1);
   // e = 2113;
   // d = 74297;

   //------------------------

   unsigned long long input = 66; // 1234;

   unsigned long long cipher;
   cout << "p = " << p << endl;
   cout << "q = " << q << endl;
   cout << "n = " << n << endl;
   cout << "z = " << z << endl;
   cout << "--------------" << endl;
   cout << "(input) m = " << input << endl;
   cout << "\npublic key(e,n) = (" << e << ", " << n << ")" << endl;
   cout << "encrypting: c = m^e mod n" << endl;
   cout << "encrypting: c = " << input << "^" << e << " mod " << n << endl;
   cipher = repeat_square(input, e, n);

   cout << "cipher c = " << cipher << endl;

   cout << "\nprivate key(d,n) = (" << d << ", " << n << ")" << endl;
   cout << "decrypting: m = c^d mod n" << endl;
   cout << "decrypting: c = " << cipher << "^" << d << " mod " << n << endl;
   unsigned long long number = repeat_square(cipher, d, n);
   cout << "decrypted value = " << number << endl;

   cout << "\n--- Analysing results ---" << endl;
   if (input == number)
   {
      cout << "We have a match, therefore correct decryption!, " << "input = " << input << ", decrypted value = " << number << endl;
   }
   else
   {
      cout << "Error in decryption!!" << "input = " << input << ", decrypted value = " << number << endl;
   }
}

// 1. RSA-CBC Encryption ->  Week 05 security_CBC and implementing RSA_CBC week 6
vector<unsigned long long> encryptRSA_CBC(const string &message, RSA *serverKey, unsigned long long nonce)
{
   vector<unsigned long long> ciphertext;
   unsigned long long previousCipher = nonce; // Initialize with nonce

   // Process char by char
   for (char c : message)
   {
      // XOR the ASCII value with previous cipher block
      unsigned long long m_xor = (unsigned long long)c ^ previousCipher;
      // Encrypt with RSA
      unsigned long long cipher = repeat_square(m_xor, serverKey->e, serverKey->n);
      // Add to ciphertext
      ciphertext.push_back(cipher);
      // Update previous cipher for next block
      previousCipher = cipher;
   }

   return ciphertext;
}

// 2. RSA-CBC Decryption
string decryptRSA_CBC(const vector<unsigned long long> &ciphertext, unsigned long long d, unsigned long long n, unsigned long long nonce)
{
   string plaintext;
   unsigned long long previousCipher = nonce; // Initialize with nonce

   for (unsigned long long cipher : ciphertext)
   {
      // Decrypt with RSA
      unsigned long long decrypted = repeat_square(cipher, d, n);
      // XOR with previous cipher block
      unsigned long long m = decrypted ^ previousCipher;
      // Convert back to char and add to plaintext
      plaintext.push_back((char)m);
      // Update previous cipher for next block
      previousCipher = cipher;
   }

   return plaintext;
}

/////////////////////////////////////////////////////////////////////
// BOOST

int128_t boost_product(long long A, long long B)
{
   int128_t ans = (int128_t)A * B;

   return ans;
}

/////////////////////////////////////////////////////////////
// Arbitrary precision data type: We can use any precision with the help of cpp_int data type if we are not sure about
// how much precision is needed in future. It automatically converts the desired precision at run-time.
cpp_int boost_factorial(int num)
{

   cpp_int fact = 1;
   for (int i = num; i > 1; --i)
      fact *= i;
   return fact;
}

////////////////////////////////////////////////////////////
template <typename T>
inline T area_of_a_circle(T r)
{
   // pi represent predefined constant having value
   // 3.1415926535897932384...
   using boost::math::constants::pi;
   return pi<T>() * r * r;
}
/////////////////////////////////////////////////////////////////////

void printBuffer(const char *header, char *buffer)
{
   std::cout << "------" << header << "------" << std::endl;
   for (unsigned int i = 0; i < strlen(buffer); i++)
   {
      if (buffer[i] == '\r')
      {
         std::cout << "buffer[" << i << "]=\\r" << std::endl;
      }
      else if (buffer[i] == '\n')
      {
         std::cout << "buffer[" << i << "]=\\n"
                   << std::endl;
      }
      else
      {
         std::cout << "buffer[" << i << "]=" << buffer[i] << std::endl;
      }
   }
   std::cout << "---" << std::endl;
}

/////////////////////////////////////////////////////////////////////

//*******************************************************************
// MAIN
//*******************************************************************
int main(int argc, char *argv[])
{

   //********************************************************************
   // Boost library test
   //********************************************************************
   // example #1:
   std::cout << "\n===========================" << std::endl;
   std::cout << "BOOST BIG NUMBER Example #1: ";
   std::cout << "\n===========================" << std::endl;

   long long first = 98745636214564698;
   long long second = 7459874565236544789;

   std::cout << "Product of " << first << " * "
             << second << " = \n"
             << boost_product(first, second);

   //-------------------------------------------------

   // INITIALIZE RSA keys and CA keys

   cout << "\n===========================" << endl;
   cout << "KEY INITIALIZATION" << endl;
   cout << "\n===========================" << endl;

   RSA *serverKey = new RSA; // Server's public and private keys
   CA *caCert = new CA;      // CA's public and private keys
   generateRSA(serverKey);
   generateCA(caCert); // CA's public and private keys

   // Nonce for the client
   unsigned long long nonce = 0;
   bool getNonce = false;

   unsigned long long cert = CreateCert(serverKey, caCert); // Server's certificate signed by CA

   if (serverKey != nullptr)
   {
      // Server's public and private keys
      displayServerKeys(serverKey); // Server's public and private keys
   }
   else
   {
      cout << "Issue: serverKey is Null " << endl;
   }

   if (caCert != nullptr)
   {

      // Server's certificate signed by CA

      displayCertificate(cert, caCert);
   }
   else
   {
      cout << "Issue: caCert is Null " << endl;
   }

   unsigned long long verified = verifyCert(cert, caCert); // Client verifies the certificate using CA's public key

   if (verified == serverKey->e) // If the decrypted value matches the server's public key
   {
      cout << "\nCertificate verified successfully!" << endl;
   }
   else
   {
      cout << "\nCertificate verification failed!" << endl;
   }

   cout << "\n===========================" << endl;

   //********************************************************************
   // INITIALIZATION of the SOCKET library
   //********************************************************************
   // this is a comment
   struct sockaddr_storage clientAddress; // IPV6

   char clientHost[NI_MAXHOST];
   char clientService[NI_MAXSERV];

   char send_buffer[BUFFER_SIZE], receive_buffer[RBUFFER_SIZE];
   int n, bytes, addrlen;
   char portNum[NI_MAXSERV];

   // char username[80];
   // char passwd[80];

   // memset(&localaddr,0,sizeof(localaddr));

#if defined __unix__ || defined __APPLE__
   int s, ns;

#elif defined _WIN32

   SOCKET s, ns;

   //********************************************************************
   // WSSTARTUP
   /*	All processes (applications or DLLs) that call Winsock functions must
      initialize the use of the Windows Sockets DLL before making other Winsock
      functions calls.
      This also makes certain that Winsock is supported on the system.
   */
   //********************************************************************
   int err;

   err = WSAStartup(WSVERS, &wsadata);
   if (err != 0)
   {
      WSACleanup();
      /* Tell the user that we could not find a usable */
      /* Winsock DLL.                                  */
      printf("WSAStartup failed with error: %d\n", err);
      exit(1);
   }

   //********************************************************************
   /* Confirm that the WinSock DLL supports 2.2.        */
   /* Note that if the DLL supports versions greater    */
   /* than 2.2 in addition to 2.2, it will still return */
   /* 2.2 in wVersion since that is the version we      */
   /* requested.                                        */
   //********************************************************************

   if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2)
   {
      /* Tell the user that we could not find a usable */
      /* WinSock DLL.                                  */
      printf("Could not find a usable version of Winsock.dll\n");
      WSACleanup();
      exit(1);
   }
   else
   {
      printf("\n\n<<<TCP SERVER>>>\n");
      printf("\nThe Winsock 2.2 dll was initialised.\n");
   }

#endif

   //********************************************************************
   // set the socket address structure.
   //
   //********************************************************************
   struct addrinfo *result = NULL;
   struct addrinfo hints;
   int iResult;

   //********************************************************************
   // STEP#0 - Specify server address information and socket properties
   //********************************************************************

   // ZeroMemory(&hints, sizeof (hints)); //alternatively, for Windows only
   memset(&hints, 0, sizeof(struct addrinfo));

   if (USE_IPV6)
   {
      hints.ai_family = AF_INET6;
   }
   else
   { // IPV4
      hints.ai_family = AF_INET;
   }

   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;
   hints.ai_flags = AI_PASSIVE; // For wildcard IP address
                                // setting the AI_PASSIVE flag indicates the caller intends to use
                                // the returned socket address structure in a call to the bind function.

   // Resolve the local address and port to be used by the server
   if (argc == 2)
   {
      iResult = getaddrinfo(NULL, argv[1], &hints, &result); // converts human-readable text strings representing hostnames or IP addresses
                                                             // into a dynamically allocated linked list of struct addrinfo structures
                                                             // IPV4 & IPV6-compliant
      sprintf(portNum, "%s", argv[1]);
      printf("\nargv[1] = %s\n", argv[1]);
   }
   else
   {
      iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); // converts human-readable text strings representing hostnames or IP addresses
                                                                  // into a dynamically allocated linked list of struct addrinfo structures
                                                                  // IPV4 & IPV6-compliant
      sprintf(portNum, "%s", DEFAULT_PORT);
      printf("\nUsing DEFAULT_PORT = %s\n", portNum);
   }

#if defined __unix__ || defined __APPLE__

   if (iResult != 0)
   {
      printf("getaddrinfo failed: %d\n", iResult);

      return 1;
   }
#elif defined _WIN32

   if (iResult != 0)
   {
      printf("getaddrinfo failed: %d\n", iResult);

      WSACleanup();
      return 1;
   }
#endif

   //********************************************************************
   // STEP#1 - Create welcome SOCKET
   //********************************************************************

#if defined __unix__ || defined __APPLE__
   s = -1;
#elif defined _WIN32
   s = INVALID_SOCKET; // socket for listening
#endif
   // Create a SOCKET for the server to listen for client connections

   s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

#if defined __unix__ || defined __APPLE__

   if (s < 0)
   {
      printf("Error at socket()");
      freeaddrinfo(result);
      exit(1); // return 1;
   }

#elif defined _WIN32

   // check for errors in socket allocation
   if (s == INVALID_SOCKET)
   {
      printf("Error at socket(): %d\n", WSAGetLastError());
      freeaddrinfo(result);
      WSACleanup();
      exit(1); // return 1;
   }
#endif
   //********************************************************************

   //********************************************************************
   // STEP#2 - BIND the welcome socket
   //********************************************************************

   // bind the TCP welcome socket to the local address of the machine and port number
   iResult = bind(s, result->ai_addr, (int)result->ai_addrlen);

#if defined __unix__ || defined __APPLE__
   if (iResult != 0)
   {
      printf("bind failed with error");
      freeaddrinfo(result);

      close(s);

      return 1;
   }

#elif defined _WIN32

   if (iResult == SOCKET_ERROR)
   {
      printf("bind failed with error: %d\n", WSAGetLastError());
      freeaddrinfo(result);

      closesocket(s);
      WSACleanup();
      return 1;
   }
#endif

   freeaddrinfo(result); // free the memory allocated by the getaddrinfo
                         // function for the server's address, as it is
                         // no longer needed
//********************************************************************

/*
   if (bind(s,(struct sockaddr *)(&localaddr),sizeof(localaddr)) == SOCKET_ERROR) {
      printf("Bind failed!\n");
   }
*/

//********************************************************************
// STEP#3 - LISTEN on welcome socket for any incoming connection
//********************************************************************
#if defined __unix__ || defined __APPLE__
   if (listen(s, SOMAXCONN) < 0)
   {
      printf("Listen failed with error\n");
      close(s);

      exit(1);
   }

#elif defined _WIN32
   if (listen(s, SOMAXCONN) == SOCKET_ERROR)
   {
      printf("Listen failed with error: %d\n", WSAGetLastError());
      closesocket(s);
      WSACleanup();
      exit(1);
   }
#endif

   //*******************************************************************
   // INFINITE LOOP
   //********************************************************************
   while (1)
   { // main loop
      printf("\n<<<SERVER>>> is listening at PORT: %s\n", portNum);
      addrlen = sizeof(clientAddress); // IPv4 & IPv6-compliant

//********************************************************************
// NEW SOCKET newsocket = accept
//********************************************************************
#if defined __unix__ || defined __APPLE__
      ns = -1;
#elif defined _WIN32
      ns = INVALID_SOCKET;
#endif

      // Accept a client socket
      // ns = accept(s, NULL, NULL);

      //********************************************************************
      // STEP#4 - Accept a client connection.
      //	accept() blocks the iteration, and causes the program to wait.
      //	Once an incoming client is detected, it returns a new socket ns
      // exclusively for the client.
      // It also extracts the client's IP address and Port number and stores
      // it in a structure.
      //********************************************************************

#if defined __unix__ || defined __APPLE__
      ns = accept(s, (struct sockaddr *)(&clientAddress), (socklen_t *)&addrlen); // IPV4 & IPV6-compliant

      if (ns < 0)
      {
         printf("accept failed\n");
         close(s);

         return 1;
      }
#elif defined _WIN32
      ns = accept(s, (struct sockaddr *)(&clientAddress), &addrlen); // IPV4 & IPV6-compliant
      if (ns == INVALID_SOCKET)
      {
         printf("accept failed: %d\n", WSAGetLastError());
         closesocket(s);
         WSACleanup();
         return 1;
      }
#endif

      printf("\nA <<<CLIENT>>> has been accepted.\n");

      memset(clientHost, 0, sizeof(clientHost));
      memset(clientService, 0, sizeof(clientService));
      getnameinfo((struct sockaddr *)&clientAddress, addrlen,
                  clientHost, sizeof(clientHost),
                  clientService, sizeof(clientService),
                  NI_NUMERICHOST);

      printf("\nConnected to <<<Client>>> with IP address:%s, at Port:%s\n", clientHost, clientService);

      //********************************************************************
      // Communicate with the Client
      //********************************************************************
      printf("\n--------------------------------------------\n");
      printf("the <<<SERVER>>> is waiting to receive messages.\n");

      cout << "\n===========================" << endl;

      //********************************************************************
      // SEND the certificate to the client
      //********************************************************************

      cout << "SERVER - Sending certificate to client" << endl;
      snprintf(send_buffer, BUFFER_SIZE, "CERT:%llu\r\n", cert); // https://stackoverflow.com/questions/3662899/understanding-the-dangers-of-sprintf
      bytes = send(ns, send_buffer, strlen(send_buffer), 0);

      // debug the header
      printBuffer("SEND_BUFFER", send_buffer);

      printf("Sent certificate: %s", send_buffer);

      printf("\n--------------------------------------------\n");

      // Wait for Client to acknowledge with ACK 226
      n = 0;
      while (1)
      {
         bytes = recv(ns, &receive_buffer[n], 1, 0);

         if ((bytes < 0) || (bytes == 0))
            break;

         if (receive_buffer[n] == '\n')
         { /*end on a LF, Note: LF is equal to one character*/
            receive_buffer[n] = '\0';
            break;
         }
         if (receive_buffer[n] != '\r')
            n++; /*ignore CRs*/
      }

      cout << "Received from client: " << receive_buffer << endl;
      printBuffer("RECEIVE_BUFFER", receive_buffer); // debug

      // Verify client acknowledged certificate receipt
      if (strncmp(receive_buffer, "ACK 226", 7) == 0)
      {
         printf("Client acknowledged certificate receipt\n");
      }
      else
      {
         printf("Negative acknowledgment\n");
         break;
      }

      //********************************************************************
      // SEND ACK 220 to client
      //********************************************************************
      cout << "SERVER - Sending ACK 220 to client" << endl;

      snprintf(send_buffer, BUFFER_SIZE, "ACK 220\r\n"); // ACK 220 to acknowledge receipt of certificate
      bytes = send(ns, send_buffer, strlen(send_buffer), 0);
      printBuffer("SEND_BUFFER", send_buffer); // debug
      cout << "Sent ACK 220: " << send_buffer << endl;
      cout << "==============================================\n";
      

      while (1)
      {
         n = 0;
         //********************************************************************
         // RECEIVE one command (delimited by \r\n)
         //********************************************************************
         while (1)
         {
            bytes = recv(ns, &receive_buffer[n], 1, 0);

            if ((bytes < 0) || (bytes == 0))
               break;

            if (receive_buffer[n] == '\n')
            { /*end on a LF, Note: LF is equal to one character*/
               receive_buffer[n] = '\0';
               break;
            }
            if (receive_buffer[n] != '\r')
               n++; /*ignore CRs*/
         }

         if ((bytes < 0) || (bytes == 0))
            break;
         sprintf(send_buffer, "Message:'%s' - There are %d bytes of information\r\n", receive_buffer, n);

         //********************************************************************
         // PROCESS REQUEST
         //********************************************************************
         printf("MSG RECEIVED <--: %s\n", receive_buffer);
         // printBuffer("RECEIVE_BUFFER", receive_buffer);

         //********************************************************************
         // SEND
         //********************************************************************
         bytes = send(ns, send_buffer, strlen(send_buffer), 0);
         printf("MSG SENT --> %s\n", send_buffer);
         // printBuffer("SEND_BUFFER", send_buffer);

#if defined __unix__ || defined __APPLE__
         if (bytes < 0)
            break;
#elif defined _WIN32
         if (bytes == SOCKET_ERROR)
            break;
#endif
      }

      //********************************************************************
      // CLOSE SOCKET
      //********************************************************************

#if defined __unix__ || defined __APPLE__
      int iResult = shutdown(ns, SHUT_WR);
      if (iResult < 0)
      {
         printf("shutdown failed with error\n");
         close(ns);

         exit(1);
      }
      close(ns);

#elif defined _WIN32
      int iResult = shutdown(ns, SD_SEND);
      if (iResult == SOCKET_ERROR)
      {
         printf("shutdown failed with error: %d\n", WSAGetLastError());
         closesocket(ns);
         WSACleanup();
         exit(1);
      }

      closesocket(ns);
#endif
      //***********************************************************************

      printf("\ndisconnected from << Client >> with IP address:%s, Port:%s\n", clientHost, clientService);
      printf("=============================================");
   } // main loop
//***********************************************************************
#if defined __unix__ || defined __APPLE__
   close(s);
#elif defined _WIN32
   closesocket(s);
   WSACleanup(); /* call WSACleanup when done using the Winsock dll */
#endif

   return 0;
}
