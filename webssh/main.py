import logging
import tornado.web
import tornado.ioloop

from tornado.options import parse_command_line, options
from webssh.handler import IndexHandler, WsockHandler
from webssh.settings import (get_app_settings, get_host_keys_settings,
                             get_policy_setting)


def make_handlers(loop, options):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)

    handlers = [
        (r'/', IndexHandler, dict(loop=loop, policy=policy,
                                  host_keys_settings=host_keys_settings)),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]
    return handlers


def make_app(handlers, app_settings):
    app = tornado.web.Application(handlers, **app_settings)
    return app


def main():
    parse_command_line()
    loop = tornado.ioloop.IOLoop.current()
    app = make_app(make_handlers(loop, options), get_app_settings(options))
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    loop.start()


if __name__ == '__main__':
    main()
