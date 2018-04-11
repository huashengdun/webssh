import logging
import tornado.web
import tornado.ioloop

from tornado.options import parse_command_line, options
from handler import IndexHandler, WsockHandler
from settings import (get_app_settings, get_host_keys_settings,
                      get_policy_setting)


def main():
    parse_command_line()
    app_settings = get_app_settings(options)
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)
    loop = tornado.ioloop.IOLoop.current()

    handlers = [
        (r'/', IndexHandler, dict(loop=loop, policy=policy,
                                  host_keys_settings=host_keys_settings)),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]

    app = tornado.web.Application(handlers, **app_settings)
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    loop.start()


if __name__ == '__main__':
    main()
