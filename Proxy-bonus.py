# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import datetime

"""
Proxy-bonus.py

Finished Bonus Question 1 Check expires

Description:
------------
- When receiving a response from the origin server, the proxy checks for the `Expires` header.
- If the `Expires` header is present and valid, the expiry time is saved in a `.meta` file along with the current timestamp.
- When requests, the proxy compares the current time with the Expires timestamp to decide whether the cached content is still valid.
- If expired or invalid, the proxy fetches a fresh copy from the origin server and updates the cache.

Relevant functions modified or added:
-------------------------------------
- `f(header_str, field_name)`: Extracts the header field value. (line 70)
- `is_cache_expired(meta_path)`: Determines if a cached object has expired. (line 76)
- Cache saving logic in the main proxy flow now stores Expires time if available. 
- Cache loading logic checks Expires time before serving the cached object.
"""

def handle_redirect_if_needed(response_data, depth=0):
    """Handle HTTP 301/302 redirection, recursively (max depth = 5)"""
    if depth > 5:
        print("Too many redirects")
        return response_data

    header_str = response_data.decode('utf-8', errors='ignore')
    status_line = header_str.split('\r\n')[0]

    if '301' in status_line or '302' in status_line:
        location = extract_header_field(header_str, 'Location')
        if location:
            print(f'Redirect detected → {location}')
            location = re.sub('^http(s?)://', '', location)
            host_and_path = location.split('/', 1)
            new_host = host_and_path[0]
            new_path = '/' + host_and_path[1] if len(host_and_path) > 1 else '/'

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((socket.gethostbyname(new_host), 80))
                req_line = f'GET {new_path} HTTP/1.1\r\nHost: {new_host}\r\nConnection: close\r\n\r\n'
                s.sendall(req_line.encode())

                redirected_response = b''
                while True:
                    chunk = s.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    redirected_response += chunk
                s.close()

                return handle_redirect_if_needed(redirected_response, depth + 1)
            except Exception as e:
                print(f"Redirect failed: {e}")
                return response_data
        else:
            print("Redirect response without Location header")
            return response_data
    else:
        return response_data

def extract_header_field(header_str, field_name):
    """extract header field from HTTP response"""
    pattern = re.compile(rf'(?i){field_name}:\s*(.*)')
    match = pattern.search(header_str)
    return match.group(1).strip() if match else None

def is_cache_expired(meta_path):
    """check whether cached file has expired"""
    if not os.path.exists(meta_path):
        return True
    try:
        with open(meta_path, "r") as meta_file:
            lines = meta_file.readlines()
            if len(lines) < 3:
                return True
            
            cache_time = float(lines[0].strip())
            max_age = int(lines[1].strip())
            expires_at = float(lines[2].strip())  # expires_at is the time when the cache expires
            
            now = datetime.datetime.now().timestamp()

            # check if the cache has expired
            if expires_at != -1:
                if now > expires_at:
                    print(f"Cache expired at ({expires_at}), now: {now}")
                    return True
                else:
                    print(f"Cache dosen't expire")
                    return False
            else:
                # check max-age
                if (now - cache_time) > max_age:
                    print(f"Cache max-age: {now - cache_time:.2f}s > {max_age}s")
                    return True
                else:
                    print(f"Cache max-age: {now - cache_time:.2f}s <= {max_age}s")
                    return False
    
    except Exception as e:
        print(f"Cache error: {e}")
        return True

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(5)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)
    metaLocation = cacheLocation + '.meta'
    if not os.path.isfile(cacheLocation) or is_cache_expired(metaLocation):
      raise Exception("Cache miss or expired")
    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    print(f'Reading cacheFile')
    cacheFile = open(cacheLocation, "rb")
    # cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    # print(f'cacheData: {cacheData}')
    # for line in cacheData:
    #   clientSocket.send(line.encode('utf-8', errors='ignore'))
    
    # I tried to use the rewrite the cacheData because its a list but the next few lines want to print ('> ' + cacheData), that causes an error and would go to exception
    print(f'Reading cacheData')
    cacheData = cacheFile.read()
    print(f'Finish reading cacheData')
    clientSocket.sendall(cacheData)
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    # print ('> ' + cacheData)
    print(f'> [binary data, {len(cacheData)} bytes]')
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = method + ' ' + resource + ' ' + version
      originServerRequestHeader = 'Host: ' + hostname + '\r\nConnection: close'
      # originServerRequestHeader = 'Host:' + hostname
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      # response = originServerSocket.recv(BUFFER_SIZE)
      response = b''
      while True:
          chunk = originServerSocket.recv(BUFFER_SIZE)
          if not chunk:
              break
          response += chunk

      # handle redirects
      response = handle_redirect_if_needed(response)

      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response)
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      cacheFile.write(response)
      # try to extract max-age from header and write to meta file
      try:
          header_str = response.decode('utf-8', errors='ignore')
          max_age_str = extract_header_field(header_str, 'Cache-Control')
          max_age = 0
          if max_age_str and 'max-age=' in max_age_str:
              max_age = int(max_age_str.split('max-age=')[1].split(',')[0].strip())
          
          # extract expires timestamp
          expires_ts = -1
          expires_str = extract_header_field(header_str, 'Expires')
          if expires_str:
            try:
              expires_ts = datetime.datetime.strptime(expires_str, "%a, %d %b %Y %H:%M:%S GMT").timestamp()
            except Exception as e:
              print(f"Error while extracting expires_ts: {e}")
              expires_ts = -1    
        
          with open(cacheLocation + '.meta', 'w') as metaFile:
              metaFile.write(str(datetime.datetime.now().timestamp()) + '\n')
              metaFile.write(str(max_age) + '\n') 
              metaFile.write(str(expires_ts if expires_ts else -1))
      except Exception as e:
          print(f"Failed to write cache meta: {e}")
      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
