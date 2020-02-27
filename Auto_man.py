#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: J0k3r
# @Date:   2020-02-28 00:39:51

import multiprocessing
import os
import queue
import subprocess
import sys
import time

import requests as req
import simplejson
from colorama import Back, Fore, Style, init

'''
一些配置参数
'''
log_name = "xlog.log"
xray_proxy =  "127.0.0.1:6666"
close_request = 0
firstStart = 1
xray_output = "{}.html".format(time.strftime("%Y.%m.%d_%H-%M-%S", time.localtime()))
xray_proxies = {
'http': 'http://127.0.0.1:6666',
'https': 'http://127.0.0.1:6666',
}

configure = {
	"chromium_path":"/Users/xc/Downloads/auto-vuln/chrome-mac/Chromium.app/Contents/MacOS/Chromium", # path to Chromium
	"crawlergo_path":"/Users/xc/Downloads/auto-vuln/crawlergo", # path to crawlergo executable file
	"xray_path":"/Users/xc/Downloads/xray/xray_darwin_amd64", # path to xray executable file
	}

args = {
	"xray_args":["webscan", "--listen", xray_proxy, "--html-output", xray_output],
	"crawlergo_args":["-c", configure["chromium_path"], "-t", "10", "-f", "smart", "--fuzz-path", "--output-mode", "json"]
	#"crawlergo_args":["-c", configure["chromium_path"], "--push-to-proxy", "http://127.0.0.1:6666", "-t", "10", "-f", "smart", "--fuzz-path", "--output-mode", "json"]
	}

template = "===> [{}] - - \"{}\" {}"
time_coclor = Fore.YELLOW + "{}" + Style.RESET_ALL
info_color = Fore.BLUE + "{}" + Style.RESET_ALL
err_color = Fore.RED + "{}" + Style.RESET_ALL
get_color = Fore.GREEN + "{}" + Style.RESET_ALL
msg_color = Fore.CYAN + "{}" + Style.RESET_ALL 

def getTime():
	return time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime())

def getCtime():
	msg_time = getTime()
	return (time_coclor.format(msg_time))

def Xlog(func):
	'''
	日志记录
	'''
	def Xlog(*args):
		with open(log_name,'a') as log_file:
			log_file.write((template.format(func.__name__, args[0], getTime())) + "\n")
		func(*args)
	return Xlog

class Cprint():
	'''
	输出类
	'''
	@staticmethod
	@Xlog
	def info(string):
		print(template.format(info_color.format("info"),msg_color.format(string),getCtime()))

	@staticmethod
	@Xlog
	def err(string):
		print(template.format(err_color.format("error"),msg_color.format(string),getCtime()))

	@staticmethod
	@Xlog
	def get(string):
		print(template.format(get_color.format("get"),msg_color.format(string),getCtime()))

def runCrawlergo(command,request_queue):
	'''
	联动 Crawlergo 
	'''
	try:
		res = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		cmd_output = bytes()
		while res.poll() is None:
			line = res.stdout.readline()
			line = line.strip()
			if line:
				#print(line)
				cmd_output += line
		try:
			crawler_data = simplejson.loads(cmd_output.decode().split("--[Mission Complete]--")[1])
		except Exception as e:
			Cprint.err(e)
			return
		request_list = crawler_data["req_list"]
		#sub_domain_list = crawler_data["sub_domain_list"] # 子域名
		for req in request_list:
			request_queue.put(req)
		Cprint.info("Crawlergo Done")
		sendRequests(request_queue)
	except Exception as e:
		Cprint.err(e)
		return

def runXray(command):
	'''
	联动 Xray 
	'''
	try:
		Cprint.info("Xray Started")
		res = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		while res.poll() is None:
			line = res.stdout.readline()
			line = line.strip()
			if line:
				print(line.decode())
	except Exception as e:
		Cprint.err(e)
		return

def urlCheck(url):
	'''
	URL 检查
	'''
	try:
		res = req.get(url,timeout=3)
		if res.status_code == 200:
			return True
	except Exception as e:
		Cprint.err("Problem with {}".format(url))
		Cprint.err(e)
		return False

def sendRequests(request_queue):
	'''
	发送请求
	'''
	Cprint.info("Send Requests")
	proxies = xray_proxies
	while True:
		if request_queue.empty() == True:
			return
		else:
			request_data = request_queue.get()
			req_url = request_data['url']
			Cprint.info("Processing {}, Remaining request: {}".format(req_url,request_queue.qsize()))
			req_header = request_data['headers']
			req_method = request_data['method']
			req_data = request_data['data']
			try:
				if(req_method=='GET'):
					req.get(req_url, headers=req_header, proxies=proxies,timeout=10,verify=False)
				elif(req_method=='POST'):
					req.post(req_url, headers=req_header,data=req_data, proxies=proxies,timeout=10,verify=False)
			except:
				continue
	return

def start(url):
	'''
	开始
	'''
	global firstStart
	request_queue = queue.Queue()
	cmd_xray = [configure["xray_path"]] + args["xray_args"] # xray 参数
	if firstStart == 1: # 启动 xray
		background_process = multiprocessing.Process(target=runXray, args=(cmd_xray,))
		background_process.daemon = False
		background_process.start()
		firstStart = 0
	Cprint.info("Target: " + url)
	Cprint.info("Starting crawlergo")
	cmd_crawlergo = [configure["crawlergo_path"]] + args["crawlergo_args"] # crawlergo 参数
	cmd_crawlergo.append(url)
	runCrawlergo(cmd_crawlergo,request_queue)
	Cprint.get(url + " Done")

if __name__ == "__main__":
	'''
	python3 Auto_man.py [url/url_file]
	'''
	if len(sys.argv) == 2:
		para = sys.argv[1]
		if os.path.isfile(para):
			with open(para,'r') as urlfile:
				for url in urlfile.readlines():
					url = url.strip()
					if urlCheck(url):
						start(url)
		else:
			if urlCheck(para):
				start(para)
	print("help: python3 Auto_man.py [url/url_file]")