# -*- coding: UTF-8 -*-
import MySQLdb

def connection():
	conn = MySQLdb.connect(host="localhost", user="root", passwd="jxlgood", db="h3cblog",charset="utf8")
	
	
	c = conn.cursor()
	return c, conn