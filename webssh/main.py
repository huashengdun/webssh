import logging
import tornado.web
import tornado.ioloop

from tornado.options import options
from webssh.handler import IndexHandler, WsockHandler
from webssh.settings import (get_app_settings, get_host_keys_settings,
                             get_policy_setting, max_body_size)


def make_handlers(loop, options):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)

    handlers = [
        (r'/', IndexHandler, dict(loop=loop, policy=policy,
                                  host_keys_settings=host_keys_settings)),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]
    return handlers


def make_app(handlers, settings):
    return tornado.web.Application(handlers, **settings)


def main():
    options.parse_command_line()
    loop = tornado.ioloop.IOLoop.current()
    app = make_app(make_handlers(loop, options), get_app_settings(options))
    app.listen(options.port, options.address, max_body_size=max_body_size)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    loop.start()


if __name__ == '__main__':
    main()
