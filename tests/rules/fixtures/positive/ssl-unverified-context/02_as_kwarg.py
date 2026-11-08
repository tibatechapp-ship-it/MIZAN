import ssl

sock = wrap(sockaddr, ctx=ssl._create_unverified_context())
