import logging
import os.path
import uuid
import paramiko

from tornado.options import define, options
from policy import get_host_keys, get_policy_class


define('address', default='127.0.0.1', help='listen address')
define('port', default=8888, help='listen port', type=int)
define('debug', default=False, help='debug mode', type=bool)
define('policy', default='warning',
       help='missing host key policy, reject|autoadd|warning')


def get_application_settings():
    base_dir = os.path.dirname(__file__)
    filename = os.path.join(base_dir, 'known_hosts')
    host_keys = get_host_keys(filename)
    system_host_keys = get_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    policy_class = get_policy_class(options.policy)
    logging.info(policy_class.__name__)

    if policy_class is paramiko.client.AutoAddPolicy:
        host_keys.save(filename)  # for permission test
    elif policy_class is paramiko.client.RejectPolicy:
        if not host_keys and not system_host_keys:
            raise ValueError('Empty known_hosts with reject policy?')

    settings = dict(
        template_path=os.path.join(base_dir, 'templates'),
        static_path=os.path.join(base_dir, 'static'),
        cookie_secret=uuid.uuid4().hex,
        xsrf_cookies=True,
        host_keys=host_keys,
        host_keys_filename=filename,
        system_host_keys=system_host_keys,
        policy=policy_class(),
        debug=options.debug
    )

    return settings
