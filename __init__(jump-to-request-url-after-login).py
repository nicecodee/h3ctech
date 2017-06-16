# -*- coding: UTF-8 -*-
from flask import Flask, render_template, flash, request, url_for, session,redirect, session, send_from_directory
from wtforms import Form, BooleanField, TextField, PasswordField, validators, RadioField
from wtforms.validators import DataRequired, Length
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
import gc
import datetime, time
from functools import wraps
import json
import os
import requests
import sys 
from content_mgmt import Content
from dbconnect import connection
from config import SECRET_KEY, instance_path, LOGS_PATH

TOPIC_DICT = Content()


app = Flask(__name__, instance_path)
app.secret_key=SECRET_KEY

#get the location from user's ip
def get_ip_info(ip):
	
	ip_info = ''
	#淘宝IP地址库接口
	r = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=%s' %ip)
	if  r.json()['code'] == 0 :
		i = r.json()['data']

		country = i['country']  #国家 
		# area = i['area']        #区域
		region = i['region']    #地区
		city = i['city']        #城市
		isp = i['isp']          #运营商
		
		ip_info = country + '/' + region + '/' + city + '/' + isp
	return ip_info


#do the logging when a user logs in
def write_log_info(info_type):
	try:
		c, conn = connection()
		
		timestr_filename = time.strftime("%Y%m%d", time.localtime())
		path = LOGS_PATH + 'user_accessed_' +  timestr_filename + '.log'
		timestr_logon = time.strftime("%Y/%m/%d-%H:%M:%S-%p", time.localtime())

		with open(path, 'ab') as file:
			if 'logged_in' in session:
				c.execute("select * from users where username = (%s)", [session['username']])
				
				ip_addr = request.remote_addr
				ip_loc = get_ip_info(ip_addr)
				ip_loc = ip_loc.encode('utf-8')  #先解决中文乱码问题
				
				#get the auth_type of first record
				username_db = c.fetchone()[1] 
				
				#write logs according to the info_type
				if 'login' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 登入'
				elif 'register' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 注册并登入'
				elif 'logout' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 退出'
				elif 'server' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 访问了服务器岗文档'
				elif 'serverDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 尝试访问服务器岗文档库被系统拒绝'
				elif 'network' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 访问了网络岗文档库'
				elif 'networkDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 尝试访问网络岗文档库被系统拒绝'
				elif 'inventory' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 访问了资产岗文档库'
				elif 'inventoryDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + ' 尝试访问资产岗文档库被系统拒绝'
					
				file.write(data + '\n') 

	except Exception as e:
		return str(e)
		

#check if user has logged in
def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			#record the url I want to access
			session["want_url"] = request.url
			
			flash("You need to login first")
			return redirect(url_for('login_page'))			
			
	return wrap
	
	
#only logged in user(s) can access the protected directory
@app.route('/protected_dir/<path:filename>')
@login_required
def protected(filename):
	try:
		return send_from_directory(os.path.join(app.instance_path, ''), filename)
	except Exception as e:
		return redirect(url_for('homepage'))

		
	
@app.route("/")
def homepage():
	return  render_template("main.html", title=u'首页')
	
@app.route("/about-team/")
def about_team():
	return  render_template("about-team.html", title=u'团队介绍')
	

@app.route("/sys-admin/")
def sys_admin():
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check auth_type of the logged in user, if not matches, redirect to role_error_page
	if 'sysadm' == auth_type_db:
		write_log_info('server')
		return  render_template("sys-admin.html", title=u'系统管理')
	else:
		write_log_info('sysadmDenied')
		return redirect(url_for('role_error_page'))	


	
@app.route('/user-auth-edit/<username>/', methods = ['GET','POST'])
def user_auth_edit(username):
	error = ''
	try:
		reload(sys)
		sys.setdefaultencoding('utf-8')
		
		username=username
		c, conn = connection()
		if request.method == "POST":
			permit = request.values.get("user_auth")
		
			#Be carefule!! Must use [] to quote username , otherwise it will
			#prompt a warning like: "not all arguments converted during string formatting"
			c.execute("update users set auth_type='%s' where username='%s'" % (permit,username) )
			conn.commit()
			
			c.close()
			conn.close()
			gc.collect()
			flash('user authorization updated successfully!')
			return  redirect(url_for('users_list'))
		else:
			c, conn = connection()
			c.execute("select * from users where username = (%s)", [username])
			auth_type_db = c.fetchone()[5] 
			return render_template("user-auth-edit.html", title=u'用户权限', auth_type_db=auth_type_db,username=username, error=error)
	
	except Exception as e:
		return str(e)

		
@app.route('/user-delete/<username>/')
@app.route('/user-delete/')
def user_delete(username):
	try:
		reload(sys)
		sys.setdefaultencoding('utf-8')
		
		username=username
		c, conn = connection()

		#Be carefule!! Must use [] to quote username , otherwise it will
		#prompt a warning like: "not all arguments converted during string formatting"
		# c.execute("delete from users where username='%s'" % (username) )
		c.execute("delete from users where username= (%s)", [username] )
		conn.commit()
		
		c.close()
		conn.close()
		gc.collect()
		flash('user deleted successfully!')
		return  redirect(url_for('users_list'))
	
	except Exception as e:
		return str(e)		

	
		
@app.route("/users-list/")
def users_list():
	try:
		c, conn = connection()

		#get all users
		c.execute("select `username`, `auth_type`, `email`, `regdate`  from users")
		users_db = c.fetchall()
		
		return render_template("users-list.html", title=u'用户列表', users_db=users_db)	
	except Exception as e:
		return str(e)


@app.route("/logs-list/")
def logs_list():
	list = []
	for logfile in os.listdir(LOGS_PATH):
		list.append(logfile)
	return  render_template("logs-list.html", title=u'日志列表', list=list)			
		
		
@app.route('/show-log/<filename>/')
@app.route("/show-log/") 
def show_log(filename):
	try:
	
		list = []
		for logfile in os.listdir(LOGS_PATH):
			list.append(logfile)
			
		fn = filename
		
		reload(sys)
		sys.setdefaultencoding('utf-8')
		
		path = LOGS_PATH + fn
		with open(path, 'r') as file:
			event_lines = file.readlines()

		data = []
		num = len(event_lines)

		for x in range(num):
			data.append(event_lines[x].split(" "))
		
		return  render_template("show-log.html", title=u'系统日志', num=num, data=data, list=list, fn=fn)
		
	except Exception as e: 
		return str(e)
	
	
@app.route("/comments/")
def comments():
	try:
		error = ''
		# user_enter_log()

		return  render_template("comments.html", title=u'留言板', error = error)
	except Exception as e:
		return str(e)
	

@app.route("/privacy/")
def privacy():
	return  render_template("privacy.html", title=u'网站规定和隐私协议')
	
	

	
@app.route("/role-error/")
def role_error_page():
	try:
		auth_type_db = ''
		c, conn = connection()
		#Be carefule!! Must use [] to quote session['username'] , otherwise it will
		#prompt a warning like: "not all arguments converted during string formatting"
		c.execute("select * from users where username = (%s)", [session['username']])
		#get the auth_type of first record
		auth_type_db = c.fetchone()[5] 

		
		return  render_template("role-error.html", title=u'权限错误', auth_type_db=auth_type_db)	
	except Exception as e:
		return str(e)
	
	
#Server docs viewing
@app.route("/server-dashboard/")
@login_required
def server_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check auth_type of the logged in user, if not matches, redirect to role_error_page
	if 'ser' == auth_type_db or 'adm' == auth_type_db or 'sysadm' == auth_type_db:
		write_log_info('server')
		return  render_template("server-dashboard.html", title=u'服务器岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		write_log_info('serverDenied')
		return redirect(url_for('role_error_page'))	


@app.route("/server-issue-handle/")
@login_required
def server_issue_handle():
	return  render_template("docs_html/server-issue-handle.html", TOPIC_DICT = TOPIC_DICT)

	
#Network docs viewing	
@app.route("/network-dashboard/")
@login_required
def network_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check if auth_type matches
	if 'net' == auth_type_db or 'adm' == auth_type_db or 'sysadm' == auth_type_db:
		write_log_info('network')
		return  render_template("network-dashboard.html", title=u'网络岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		write_log_info('networkDenied')
		return redirect(url_for('role_error_page'))	
	


#Inventory docs viewing	
@app.route("/inventory-dashboard/")
@login_required
def inventory_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check if auth_type matches
	if 'inv' == auth_type_db or 'adm' == auth_type_db or 'sysadm' == auth_type_db:
		write_log_info('inventory')
		return  render_template("inventory-dashboard.html", title=u'资产岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		write_log_info('inventoryDenied')
		return redirect(url_for('role_error_page'))	
		
	
@app.errorhandler(404)
def page_not_found(e):
	return  render_template("404.html")
	

	
@app.route("/logout/")
@login_required
def logout():
	write_log_info('logout') #do the logging
	
	session.clear()
	flash("You have been logged out!")
	gc.collect()
	return redirect(url_for('homepage'))

	
@app.route("/login/", methods = ['GET','POST'])
def login_page():
	error = ''
	try:
		reload(sys)
		sys.setdefaultencoding('utf-8')
		
		c, conn = connection()
		if request.method == "POST":
			#Be carefule!! Must use [] to quote thwart(request.form['username']), otherwise it will
			#prompt a warning like: "not all arguments converted during string formatting"
			c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			#get the password of first record
			pwd_in_db = c.fetchone()[2]
			
			#get the auth_type_db of logged in user
			c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			auth_type_db = c.fetchone()[5]
			
			#check if password matches
			if sha256_crypt.verify(request.form['password'], pwd_in_db):
				session['logged_in'] = True
				session['username'] = request.form['username']
				session['auth_type_db'] = auth_type_db
				
				write_log_info('login')  #do the logging
				flash("You are now logged in!")
				

				#redirect to the exact url I want to access
				return redirect(session["want_url"])

				
			else:
				error = u'身份验证失败，请重试!'
		
		gc.collect()	
		
		return render_template("login.html", title=u'登陆', error=error)
		
	except Exception as e:
		error = error = u'身份验证失败，请重试!'
		return  render_template("login.html", title=u'登陆', error = error)


class RegistrationForm(Form):
	username = TextField(u'用户名', [validators.Length(min=4, max=20)])
	email = TextField(u'邮箱', [validators.Length(min=8, max=50)])
	password = PasswordField(u'密码', [validators.Required(),validators.Length(min=6, max=30),
				validators.EqualTo('confirm', message=u'密码不匹配')])	
	confirm = PasswordField(u'重输一遍密码')
	accept_tos = BooleanField(u'我接受<a href="/privacy/">网站规定和隐私协议</a> (最后更新：2016年7月)', [validators.Required()])
	
	
@app.route("/register/", methods = ['GET','POST'])
def register_page():
	try:
		reload(sys)
		sys.setdefaultencoding('utf-8')
		form = RegistrationForm(request.form)
		
		if request.method == "POST" and form.validate():
			username = form.username.data
			password = sha256_crypt.encrypt((str(form.password.data))) 
			email = form.email.data
			c, conn = connection()

			x = c.execute("select * from users where username = (%s)", [thwart(username)])
			if int(x) > 0:
				flash("username taken! Try another one!")
				return render_template('register.html', title=u'注册', form=form)
			else:
				#get the date of registeration, use China time
				datenow = datetime.datetime.utcnow()
				
				c.execute("insert into users (username, password, email, regdate) values (%s,%s,%s,%s)", (thwart(username), thwart(password), thwart(email), datenow))
				conn.commit()
				
				flash("Thanks for registering!")
				c.close()
				conn.close()
				gc.collect()
				
				session['logged_in'] = True
				session['username'] = username

				
				write_log_info('register') #do the logging
				
				return redirect(url_for('homepage'))
		
		return render_template("register.html", title=u'注册', form=form)
		
	except Exception as e:
		return(str(e))


		
	
if __name__ == "__main__":
	app.run()