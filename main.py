import logging
import tornado.web
import tornado.ioloop

from tornado.options import parse_command_line, options
from handler import IndexHandler, WsockHandler
from settings import get_application_settings


def main():
    parse_command_line()
    settings = get_application_settings()

    handlers = [
        (r'/',   IndexHandler),
        (r'/ws', WsockHandler)
    ]

    loop = tornado.ioloop.IOLoop.current()
    app = tornado.web.Application(handlers, **settings)
    app._loop = loop
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    loop.start()


if __name__ == '__main__':
    main()
