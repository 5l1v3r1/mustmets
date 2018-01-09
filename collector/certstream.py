"""
Must Mets - Real-time DNSBL from CT log mining
Copyright (C) 2018 Silver Saks

Certstream module - connects to the certstream provided by http://certstream.calidog.io/ to receive certificates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
import asyncio
import ssl


class MyClientProtocol(WebSocketClientProtocol):

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))

    def onOpen(self):
        print("WebSocket connection open.")

    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
        else:
            self.factory.callback(payload.decode('utf8'))

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))
        self.factory.loop.stop()


def listen_for_events(callback):
    try:
        while True:
            print("Attempting to open websocket connection")
            factory = WebSocketClientFactory(u"wss://certstream.calidog.io")
            factory.setProtocolOptions(openHandshakeTimeout=10, tcpNoDelay=True)
            factory.protocol = MyClientProtocol
            factory.callback = callback

            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = True

            loop = asyncio.get_event_loop()
            coro = loop.create_connection(factory, 'certstream.calidog.io', 443, ssl=ssl_context)
            loop.run_until_complete(coro)
            loop.run_forever()
    except KeyboardInterrupt:
        loop.stop()
        loop.close()

