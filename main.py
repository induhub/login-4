#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
from google.appengine.ext import ndb
import logging
import hashlib
import random
import string

jinja_environment = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

class Users(ndb.Model):
    username = ndb.StringProperty(required=True)
    hash = ndb.TextProperty(required=True)
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(username, password):
    salt=make_salt()
    val=hashlib.sha256(username+password+salt).hexdigest()
    return '%s|%s' % (val,salt)


def MainHandler(self):
    def get(self):
        self.response.headers["Content-Type"]='text\plain'
        cookie = self.request.cookies.get('username',None)
        self.response.headers.add_header('Set-Cookie' , cookie)
        self.write("welcome!!")

        
class SignupHandler(webapp2.RequestHandler):
    def get(self):
        template = jinja_environment.get_template('signup.html')
        context = {}
        html = template.render(context)
        self.response.write(html)
        
    def post(self):
        new_user_name = self.request.get("username")
        user_exists=Users.query(Users.username==new_user_name).get()
        print '#####################################'
        logging.warning(str(user_exists))
        print '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
        if user_exists == None:         
            new_password = self.request.get("password")
            if new_password=="":
                template = jinja_environment.get_template('signup.html')
                context = {'password_error': "password theek se bhar!"}
                html = template.render(context)
                self.response.write(html)
            else:  
                new_user = Users(username=new_user_name,hash=make_pw_hash(new_user_name,new_password))                
                new_user.put()
                cookie_value = new_user_name+'|'+make_pw_hash(new_user_name,"")
                cookie = 'username='+cookie_value+';Path = /'
                self.response.headers.add_header('Set-Cookie' , str(cookie))
                self.redirect("/welcome")
            
        else:
            template = jinja_environment.get_template('signup.html')
            context = {'userid_error': "user_id already taken"}
            html = template.render(context)
            self.response.write(html)


class WelcomeHandler(webapp2.RequestHandler):                                   
    def get(self):
        cookie_value = self.request.cookies.get('username',None).split('|')
        username = cookie_value[0]
        salt = cookie_value[2]
        h = cookie_value[1]
        if h==hashlib.sha256(username+ ""+ salt).hexdigest():
            self.response.write("welcome "+ username+ '<a href="/logout">Logout!!</a>')
        else:
            self.redirect("/signup")
                 
class LoginHandler(webapp2.RequestHandler):
    def get(self):
        template = jinja_environment.get_template('login.html')
        context = {'userid_error': "user_id already taken"}
        html = template.render(context)
        self.response.write(html)
        
    def post(self):
        username = self.request.get("username")
        password=self.request.get("password")
        
        #encr=hashlib.sha256(username+password+salt).hexdigest()
        user_exists=Users.query(Users.username==username).get()
        hash = user_exists.hash.split('|')
        salt = hash[1]
        encr = hash[0]
        if encr==hashlib.sha256(username+password+salt).hexdigest():
            #log him in
            cookie_value = username+'|'+make_pw_hash(username,"")
            cookie = 'username='+cookie_value+';Path = /'
            self.response.headers.add_header('Set-Cookie' , str(cookie))
            self.redirect('/welcome')
        else:
            template = jinja_environment.get_template('login.html')
            context = {'login_error': "login failed"}
            html = template.render(context)
            self.response.write(html)

class LogoutHandler(webapp2.RequestHandler):
    def get(self):  
        cookie = 'username='+""+';Path = /'
        self.response.headers.add_header('Set-Cookie' , str(cookie))
        self.redirect('/signup')           

    
app = webapp2.WSGIApplication([
    ('/signup',SignupHandler),('/welcome',WelcomeHandler),('/login',LoginHandler),('/logout',LogoutHandler)
], debug=True)
