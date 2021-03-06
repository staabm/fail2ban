# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import commands
from faildata import FailData
from ticket import FailTicket
from threading import Lock
import logging


# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

class FailManager:
	
	def __init__(self):
		self.__lock = Lock()
		self.__failList = dict()
		self.__maxRetry = 3
		self.__maxTime = 600
		self.__failTotal = 0
		self.__mostIP = 0 # AD
		self.__mostRetry = 0 # AD
		self.__sumRetry = 0 # AD
		self.__samplesRetry = 0 # AD
		self.__lastRRDUpdateTime = 0 # AD
		self.__updateTime = 59 # AD
		self.__updateLastTimeStamp = 0 # AD
	
	def setFailTotal(self, value):
		try:
			self.__lock.acquire()
			self.__failTotal = value
		finally:
			self.__lock.release()
		
	def getFailTotal(self):
		try:
			self.__lock.acquire()
			return self.__failTotal
		finally:
			self.__lock.release()
	
	def setMaxRetry(self, value):
		try:
			self.__lock.acquire()
			self.__maxRetry = value
		finally:
			self.__lock.release()
	
	def getMaxRetry(self):
		try:
			self.__lock.acquire()
			return self.__maxRetry
		finally:
			self.__lock.release()
	
	def setMaxTime(self, value):
		try:
			self.__lock.acquire()
			self.__maxTime = value
		finally:
			self.__lock.release()
	
	def getMaxTime(self):
		try:
			self.__lock.acquire()
			return self.__maxTime
		finally:
			self.__lock.release()

	def addFailure(self, ticket):
		try:
			self.__lock.acquire()
			ip = ticket.getIP()
			unixTime = ticket.getTime()
			matches = ticket.getMatches()
			# AD START
			if logSys.isEnabledFor(logging.INFO) or logSys.isEnabledFor(logging.DEBUG) :
				# INIT & CLEAN UP
				if self.__updateLastTimeStamp == 0:
					self.__updateLastTimeStamp = unixTime
				if self.__lastRRDUpdateTime == 0:
					self.__lastRRDUpdateTime = unixTime
				if self.__samplesRetry > 1000000:
					self.__sumRetry = 0
					self.__samplesRetry = 0 
				# CHECK LAST UPDATE
				diffRRDTime = unixTime - self.__lastRRDUpdateTime
				if diffRRDTime > self.__updateTime:
					# UPDATE IS LONG TIME AGO - RRDTOOL UPDATE
					logSys.debug("diffRRDTime: %s" % diffRRDTime)
					logSys.debug('/usr/bin/rrdtool update /var/www/fail2ban/fail2ban_ad.rrd N:%d' %(self.__mostRetry))
					commands.getstatusoutput('/usr/bin/rrdtool update /var/www/fail2ban/fail2ban_ad.rrd N:%d' %(self.__mostRetry))
					# RESET PARAMETER
					self.__samplesRetry += (diffRRDTime%self.__updateTime)
					self.__lastRRDUpdateTime = unixTime
					if ( unixTime - self.__updateLastTimeStamp ) > ( self.__updateTime * 2 ):
						self.__mostRetry = 0
						self.__updateLastTimeStamp = unixTime
				else:
					self.__samplesRetry += 1
			# AD STOP
			if self.__failList.has_key(ip):
				fData = self.__failList[ip]
				if fData.getLastReset() < unixTime - self.__maxTime:
					fData.setLastReset(unixTime)
					fData.setRetry(0)
				fData.inc(matches)
				fData.setLastTime(unixTime)
				# AD START
				if logSys.isEnabledFor(logging.INFO) or logSys.isEnabledFor(logging.DEBUG) :
					self.__sumRetry += fData.getRetry()
					if fData.getRetry() > self.__mostRetry:
						if self.__mostIP == ip:
							self.__mostRetry = fData.getRetry()
						else:
							self.__mostRetry = fData.getRetry()
							self.__mostIP = ip
				# AD STOP
			else:
				fData = FailData()
				fData.inc(matches)
				fData.setLastReset(unixTime)
				fData.setLastTime(unixTime)
				self.__failList[ip] = fData
				# AD START
				if logSys.isEnabledFor(logging.INFO) or logSys.isEnabledFor(logging.DEBUG) :
					self.__sumRetry += 1	
				# AD STOP
			logSys.debug("Currently have failures from %d IPs: %s"
						 % (len(self.__failList), self.__failList.keys()))
			self.__failTotal += 1
		finally:
			self.__lock.release()
	
	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__failList)
		finally:
			self.__lock.release()
	
	def cleanup(self, time):
		try:
			self.__lock.acquire()
			tmp = self.__failList.copy()
			for item in tmp:
				if tmp[item].getLastTime() < time - self.__maxTime:
					self.__delFailure(item)
		finally:
			self.__lock.release()
	
	def __delFailure(self, ip):
		if self.__failList.has_key(ip):
			del self.__failList[ip]
	
	def toBan(self):
		try:
			self.__lock.acquire()
			for ip in self.__failList:
				data = self.__failList[ip]
				if data.getRetry() >= self.__maxRetry:
					self.__delFailure(ip)
					# Create a FailTicket from BanData
					failTicket = FailTicket(ip, data.getLastTime(), data.getMatches())
					failTicket.setAttempt(data.getRetry())
					return failTicket
			raise FailManagerEmpty
		finally:
			self.__lock.release()

class FailManagerEmpty(Exception):
	pass
