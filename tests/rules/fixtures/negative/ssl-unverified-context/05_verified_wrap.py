import ssl

wrapped = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED)
