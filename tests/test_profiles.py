import pytest, os, re, yaml, random
from tornado.options import options
from tornado.testing import AsyncTestCase, AsyncHTTPTestCase
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings
from tests.utils import make_tests_data_path
from yaml.loader import SafeLoader

class TestYAMLLoading(object):
   def test_profile_samples(self):
      if 'PROFILES' in os.environ: del os.environ['PROFILES']
      assert 'profiles' not in get_app_settings(options)

      os.environ['PROFILES']=make_tests_data_path('profiles-sample.yaml')
      assert 'profiles' in get_app_settings(options)
      profiles=get_app_settings(options)['profiles']['profiles']
      assert profiles[0]['name']=='sample1'
      assert profiles[0]['description']=='Long description'
      assert profiles[0]['host']=='localhost'
      assert profiles[0]['port']==22
      assert profiles[0]['username']=='robey'

      assert profiles[1]['name']=='sample2'
      assert profiles[1]['description']=='Long description'
      assert profiles[1]['host']=='localhost'
      assert profiles[1]['port']==22
      assert profiles[1]['username']=='robey'
      assert profiles[1]['private-key']==open(make_tests_data_path('user_rsa_key'), 'r').read()
      del os.environ['PROFILES']

class _TestBasic_(object):
   running = [True]
   sshserver_port = 2200
   body = 'hostname={host}&port={port}&profile={profile}&username={username}&password={password}'
   headers = {'Cookie': '_xsrf=yummy'}

   def _getApp_(self, **kwargs):
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

class TestWebGUIWithProfiles(AsyncHTTPTestCase, _TestBasic_):
   def get_app(self):
      try:
         os.environ['PROFILES']=make_tests_data_path('profiles-sample.yaml')
         return self._getApp_()
      finally:
         del os.environ['PROFILES']


   def test_get_app_settings(self):
      try:
         os.environ['PROFILES']=make_tests_data_path('profiles-sample.yaml')
         settings=get_app_settings(options)
         assert 'profiles' in settings
         profiles=settings['profiles']['profiles']
         assert profiles[0]['name']=='sample1'
         assert profiles[0]['description']=='Long description'
         assert profiles[0]['host']=='localhost'
         assert profiles[0]['port']==22
         assert profiles[0]['username']=='robey'
   
         assert profiles[1]['name']=='sample2'
         assert profiles[1]['description']=='Long description'
         assert profiles[1]['host']=='localhost'
         assert profiles[1]['port']==22
         assert profiles[1]['username']=='robey'
         assert profiles[1]['private-key']==open(make_tests_data_path('user_rsa_key'), 'r').read()
      finally:
         del os.environ['PROFILES']

   def test_without_profiles(self):
      rep = self.fetch('/')
      assert rep.code==200, 'Testing server response status code: {0}'.format(rep.code)
      assert str(rep.body).index('<!-- PROFILES -->')>=0, 'Expected the "profiles.html" but "index.html"'

class TestWebGUIWithoutProfiles(AsyncHTTPTestCase, _TestBasic_):
   def get_app(self):
      if 'PROFILES' in os.environ: del os.environ['PROFILES']
      return self._getApp_()

   def test_get_app_settings(self):
      if 'PROFILES' in os.environ: del os.environ['PROFILES']
      settings=get_app_settings(options)
      assert 'profiles' not in settings

   def test_with_profiles(self):
      rep = self.fetch('/')
      assert rep.code==200, 'Testing server response status code: {0}'.format(rep.code)
      with pytest.raises(ValueError):
         str(rep.body).index('<!-- PROFILES -->')
         assert False, 'Expected the origin "index.html" but "profiles.html"'
