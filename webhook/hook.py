#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import threading
import hashlib
import hmac
import subprocess
import logging
import os
import sys
import json

webops = None
repos = None

class websiteOperator:
    def __init__(self, server):
        self.web_root = os.path.abspath(server['webroot'])
        self.repo_path = os.path.abspath(server['path'])
        if not os.path.isdir(self.repo_path):
            logging.error("repo path %s not exist, abort", self.repo_path)
            sys.exit(1)
            
        self.hexo_path = subprocess.getoutput('which hexo')
        if not os.path.exists(self.hexo_path):
            logging.error("hexo not found, abort")
            sys.exit(1)

        self.git_path = subprocess.getoutput('which git')
        if not os.path.exists(self.git_path):
            logging.error("git not found, abort")
            sys.exit(1)

        return
    def update_posts(self):
        logging.info("update post...")
        subprocess.call([self.git_path, 'pull', 'origin', 'master'], cwd=self.repo_path + '/source')
        subprocess.call([self.git_path, 'pull', 'origin', 'master'], cwd=self.repo_path)
        subprocess.call([self.hexo_path, 'generate'], cwd=self.repo_path)
        subprocess.call(['rsync', '-avzh', self.repo_path + '/public/', self.web_root])
        return

class hook_handler(BaseHTTPRequestHandler):
    def ack(self, code):
        # ack request
        self.send_response(code)
        self.end_headers()
        return
    def secure_check(self, key, data):
        sha_name, signature = self.headers['X-Hub-Signature'].split('=')
        if sha_name != 'sha1':
            return False

        # HMAC requires its key to be bytes, but data is strings.
        mac = hmac.new(key, msg=data, digestmod=hashlib.sha1)
        return hmac.compare_digest(mac.hexdigest(), signature)
    def do_POST(self):
        # check request type
        event_type = self.headers.get("X-Github-Event")
        if event_type != 'push':
            logging.warning("ignore github event %s", event_type)
            self.ack(200)
            return

        post_type = self.headers.get('Content-Type')
        if (post_type == 'application/x-www-form-urlencoded') or (post_type == 'application/json'):
            length = int(self.headers.get('Content-Length'))
            post_data = self.rfile.read(length)
        else:
            logging.warning("ignore unkwown content-type %s", post_type)
            self.ack(200)
            return

        payload = json.loads(post_data.decode('utf-8'))
        if repos['name'] == payload['repository']['full_name']:
            if (repos['hmac'] == 1):
                if not self.secure_check(str.encode(repos['key']), post_data):
                    logging.error("HMAC check failed")
                    self.ack(401)
                    return
            threading.Thread(target=webops.update_posts).start()
        else:
            logging.warning("unkown push event from %s", payload['repository']['full_name'])

        self.ack(200)
        return
    def do_GET(self):
        self.send_response(405)
        self.end_headers()
        return

if __name__ == '__main__':
    location = os.path.dirname(os.path.realpath(__file__))

    if not os.path.exists(location + '/log'):
        os.makedirs(location + '/log')

    sys.stdout = open(location + '/log/access.log', 'w')
    sys.stderr = open(location + '/log/error.log', 'w')
    logging.basicConfig(filename=location + '/log/details.log', level=logging.INFO, format='%(asctime)s.%(msecs)d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    config = json.load(open(location + '/hook.conf'))

    repos = config['repo']
    webops = websiteOperator(config['server'])
    server = HTTPServer(('', config['server']['port']), hook_handler)
    server.server_version = "TinyLab/1.0"
    server.sys_version = "Unknown"
    logging.info("Starting server at port %d", config['server']['port'])
    server.serve_forever()
