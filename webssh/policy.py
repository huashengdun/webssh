import logging
import os.path
import threading
import paramiko


def load_host_keys(path):
    if os.path.exists(path) and os.path.isfile(path):
        return paramiko.hostkeys.HostKeys(filename=path)
    return paramiko.hostkeys.HostKeys()


def get_policy_dictionary():
    dic = {
       k.lower(): v for k, v in vars(paramiko.client).items() if type(v)
       is type and issubclass(v, paramiko.client.MissingHostKeyPolicy)
       and v is not paramiko.client.MissingHostKeyPolicy
    }
    return dic


def get_policy_class(policy):
    origin_policy = policy
    policy = policy.lower()
    if not policy.endswith('policy'):
        policy += 'policy'

    dic = get_policy_dictionary()
    logging.debug(dic)

    try:
        cls = dic[policy]
    except KeyError:
        raise ValueError('Unknown policy {!r}'.format(origin_policy))
    return cls


def check_policy_setting(policy_class, host_keys_settings):
    host_keys = host_keys_settings['host_keys']
    host_keys_filename = host_keys_settings['host_keys_filename']
    system_host_keys = host_keys_settings['system_host_keys']

    if policy_class is paramiko.client.AutoAddPolicy:
        host_keys.save(host_keys_filename)  # for permission test
    elif policy_class is paramiko.client.RejectPolicy:
        if not host_keys and not system_host_keys:
            raise ValueError(
                'Reject policy could not be used without host keys.'
            )


class AutoAddPolicy(paramiko.client.MissingHostKeyPolicy):
    """
    thread-safe AutoAddPolicy
    """
    lock = threading.Lock()

    def is_missing_host_key(self, client, hostname, key):
        k = client._system_host_keys.lookup(hostname) or \
                client._host_keys.lookup(hostname)
        if k is None:
            return True
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return True
        if host_key != key:
            raise paramiko.BadHostKeyException(hostname, key, host_key)

    def missing_host_key(self, client, hostname, key):
        with self.lock:
            if self.is_missing_host_key(client, hostname, key):
                keytype = key.get_name()
                logging.info(
                    'Adding {} host key for {}'.format(keytype, hostname)
                )
                client._host_keys._entries.append(
                    paramiko.hostkeys.HostKeyEntry([hostname], key)
                )

                with open(client._host_keys_filename, 'a') as f:
                    f.write('{} {} {}\n'.format(
                        hostname, keytype, key.get_base64()
                    ))


paramiko.client.AutoAddPolicy = AutoAddPolicy
