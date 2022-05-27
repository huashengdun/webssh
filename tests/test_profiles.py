import unittest, yaml, tornado.websocket, tornado.gen, threading, random, json, os
from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options

from tests.utils import make_tests_data_path
from yaml.loader import SafeLoader

from webssh import handler 
from webssh.main import make_app, make_handlers
from webssh.utils import to_str
from webssh.settings import (
    get_app_settings, get_server_settings, max_body_size
)

from tests.sshserver import run_ssh_server, banner, Server
from tests.test_app import TestAppBase

class TestProfiles(TestAppBase):
   running = [True]
   sshserver_port = 2200
   body = 'hostname={host}&port={port}&profile={profile}&username={username}&password={password}'
   headers = {'Cookie': '_xsrf=yummy'}

   def get_app(self):
      self.body_dict = {
         'hostname': '127.0.0.1',
         'port': str(self.sshserver_port),
         'username': 'robey',
         'password': '',
         '_xsrf': 'yummy'
      }
      loop = self.io_loop
      options.debug = False
      options.policy = random.choice(['warning', 'autoadd'])
      options.hostfile = ''
      options.syshostfile = ''
      options.tdstream = ''
      options.delay = 0.1
      #options.profiles=make_tests_data_path('tests/data/profiles-sample.yaml')
      app = make_app(make_handlers(loop, options), get_app_settings(options))
      return app

   def test_app_4_profiles_reading(self):
      if 'PROFILES' in os.environ: del os.environ['PROFILES']
      assert 'profiles' not in get_app_settings(options)

      os.environ['PROFILES']=make_tests_data_path('profiles-sample.yaml')
      assert 'profiles' in get_app_settings(options)
      profiles=get_app_settings(options)['profiles']
      assert profiles[0]['name']=='sample1'
      assert profiles[0]['description']=='Long description'
      assert profiles[0]['host']=='localhost'
      assert profiles[0]['port']==22
      assert profiles[0]['username']=='user'
      assert profiles[0]['private_key']==open(make_tests_data_path('user_rsa_key'), 'r').read()

      assert profiles[1]['name']=='sample2'
      assert profiles[1]['description']=='Long description'
      assert profiles[1]['host']=='localhost'
      assert profiles[1]['port']==22
      assert profiles[1]['username']=='user'
      del os.environ['PROFILES']

   @classmethod
   def setUpClass(cls):
      print('='*20)
      t = threading.Thread(
         target=run_ssh_server, args=(cls.sshserver_port, cls.running)
      )
      t.setDaemon(True)
      t.start()

   @classmethod
   def tearDownClass(cls):
      cls.running.pop()
      print('='*20)

   def _testBody_(self, body):
      url = self.get_url('/')
      response = yield self.async_post(url, body)
      data = json.loads(to_str(response.body))
      self.assert_status_none(data)

      url = url.replace('http', 'ws')
      ws_url = url + 'ws?id=' + data['id']
      ws = yield tornado.websocket.websocket_connect(ws_url)
      msg = yield ws.read_message()
      self.assertEqual(to_str(msg, data['encoding']), banner)

      # messages below will be ignored silently
      yield ws.write_message('hello')
      yield ws.write_message('"hello"')
      yield ws.write_message('[hello]')
      yield ws.write_message(json.dumps({'resize': []}))
      yield ws.write_message(json.dumps({'resize': {}}))
      yield ws.write_message(json.dumps({'resize': 'ab'}))
      yield ws.write_message(json.dumps({'resize': ['a', 'b']}))
      yield ws.write_message(json.dumps({'resize': {'a': 1, 'b': 2}}))
      yield ws.write_message(json.dumps({'resize': [100]}))
      yield ws.write_message(json.dumps({'resize': [100]*10}))
      yield ws.write_message(json.dumps({'resize': [-1, -1]}))
      yield ws.write_message(json.dumps({'data': [1]}))
      yield ws.write_message(json.dumps({'data': (1,)}))
      yield ws.write_message(json.dumps({'data': {'a': 2}}))
      yield ws.write_message(json.dumps({'data': 1}))
      yield ws.write_message(json.dumps({'data': 2.1}))
      yield ws.write_message(json.dumps({'key-non-existed': 'hello'}))
      # end - those just for testing webssh websocket stablity

      yield ws.write_message(json.dumps({'resize': [79, 23]}))
      msg = yield ws.read_message()
      self.assertEqual(b'resized', msg)

      yield ws.write_message(json.dumps({'data': 'bye'}))
      msg = yield ws.read_message()
      self.assertEqual(b'bye', msg)
      ws.close()
   
   @tornado.testing.gen_test
   def test_profile_with_username(self):
      body=self.body.format(
         host="127.0.0.1",
         port=22,
         username="robey",
         password="foo",
         profile="",
      )
      self._testBody_(body)

   @tornado.testing.gen_test
   def test_profile_with_privatekey(self):
      body=self.body.format(
         host="127.0.0.1",
         port=22,
         username="robey",
         password="",
         profile="",
      )
      self._testBody_(body)
