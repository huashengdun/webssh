import logging
import tornado.web
import tornado.ioloop
from tornado.httpserver import HTTPServer

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


def http_server_arguments():
    http_server_kwargs = {"max_body_size": max_body_size}
    if options.trusted_downstream and len(options.trusted_downstream) > 0:
        trusted_downstream = str(options.trusted_downstream).split(",")
    else:
        trusted_downstream = []

    if trusted_downstream and len(trusted_downstream) > 0:
        http_server_kwargs["xheaders"] = True
        http_server_kwargs["trusted_downstream"] = trusted_downstream
    return http_server_kwargs


def main():
    options.parse_command_line()
    http_server_kwargs = http_server_arguments()

    loop = tornado.ioloop.IOLoop.current()
    app = make_app(make_handlers(loop, options), get_app_settings(options))
    server = HTTPServer(app, **http_server_kwargs)
    server.listen(options.port, options.address)

    logging.info('Listening on {}:{}'.format(options.address, options.port))
    loop.start()


if __name__ == '__main__':
    main()
