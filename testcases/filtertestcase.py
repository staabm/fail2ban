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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
#
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
import time
from server.filterpoll import FilterPoll
from server.filter import FileFilter
from server.failmanager import FailManager
from server.failmanager import FailManagerEmpty

class IgnoreIP(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FileFilter(None)

	def tearDown(self):
		"""Call after every test case."""

	def testIgnoreIPOK(self):
		ipList = "127.0.0.1", "192.168.0.1", "255.255.255.255", "99.99.99.99"
		for ip in ipList:
			self.__filter.addIgnoreIP(ip)
			self.assertTrue(self.__filter.inIgnoreIPList(ip))
		# Test DNS
		self.__filter.addIgnoreIP("www.epfl.ch")
		self.assertTrue(self.__filter.inIgnoreIPList("128.178.50.12"))

	def testIgnoreIPNOK(self):
		ipList = "", "999.999.999.999", "abcdef", "192.168.0."
		for ip in ipList:
			self.__filter.addIgnoreIP(ip)
			self.assertFalse(self.__filter.inIgnoreIPList(ip))
		# Test DNS
		self.__filter.addIgnoreIP("www.epfl.ch")
		self.assertFalse(self.__filter.inIgnoreIPList("127.177.50.10"))


class LogFile(unittest.TestCase):

	FILENAME = "testcases/files/testcase01.log"

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FilterPoll(None)
		self.__filter.addLogPath(LogFile.FILENAME)

	def tearDown(self):
		"""Call after every test case."""

	#def testOpen(self):
	#	self.__filter.openLogFile(LogFile.FILENAME)

	def testIsModified(self):
		self.assertTrue(self.__filter.isModified(LogFile.FILENAME))


class GetFailures(unittest.TestCase):

	FILENAME_01 = "testcases/files/testcase01.log"
	FILENAME_02 = "testcases/files/testcase02.log"
	FILENAME_03 = "testcases/files/testcase03.log"
	FILENAME_04 = "testcases/files/testcase04.log"

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FileFilter(None)
		self.__filter.setActive(True)
		# let it look for 1 year back since log files have no years
		# and those change from year to year, while tickets take
		# current year
		self.__filter.setFindTime(365 * 24 * 60 * 60)

		# TODO Test this
		#self.__filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.__filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""
		pass

	def testGetFailures01(self):
		outputs = (
			('87.142.124.10', 4, 12, 31), # ip, #failures, month, day
			('193.168.0.128', 6,          # 3 in matching locale and 3 from Aug
			 None,	  # we cannot check month reliably since the
			 None),   # latest reported and we have Dec and Aug
			('192.0.43.10',   3, 12, 31)  # for example.com
			)
		self.__filter.addLogPath(GetFailures.FILENAME_01)
		self.__filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_01)

		for ip, attempts, mon, mday in outputs:
			ticket = self.__filter.failManager.toBan()

			date = time.localtime(ticket.getTime())

			self.assertEqual(ticket.getIP(), ip)
			self.assertEqual(ticket.getAttempt(), attempts)
			if mon:
				self.assertEqual(date.tm_mon, mon)
				self.assertEqual(date.tm_mday, mday)

		# and there should be no more
		self.failUnlessRaises(FailManagerEmpty, self.__filter.failManager.toBan)

	def testGetFailures02(self):
		outputs = (('141.3.81.106', 4, 1124013539.0),
				   # ('66.38.192.238', 1, 1) # we need 3 according to maxRetry
				   )

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")

		self.__filter.getFailures(GetFailures.FILENAME_02)

		for ip, attempts, _ in outputs:
			ticket = self.__filter.failManager.toBan()

			attempts = ticket.getAttempt()
			ip = ticket.getIP()

			self.assertEqual(ticket.getIP(), ip)
			self.assertEqual(ticket.getAttempt(), attempts)
			# no time comparison  			date = ticket.getTime()

		# and there should be no more
		self.failUnlessRaises(FailManagerEmpty, self.__filter.failManager.toBan)

	def testGetFailures03(self):
		output = (u'203.162.223.135', 8, # yoh: mysteriously it matches
				  1124013544.0)

		self.__filter.addLogPath(GetFailures.FILENAME_03)
		self.__filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")

		self.__filter.getFailures(GetFailures.FILENAME_03)

		ticket = self.__filter.failManager.toBan()

		attempts = ticket.getAttempt()
		# we can't match the date
		date = output[-1]
		ldate = time.localtime(ticket.getTime())
		ip = ticket.getIP()
		found = (ip, attempts, date)

		self.assertEqual(found, output)
		self.assertEqual(8, ldate.tm_mon)
		self.assertEqual(14, ldate.tm_mday)
		self.assertEqual(12, ldate.tm_hour)

	def testGetFailures04(self):
		outputs = [('212.41.96.186', 4, 1313337600.0),
				   ['212.41.96.185', 7, None]]

		self.__filter.addLogPath(GetFailures.FILENAME_04)
		self.__filter.addFailRegex("Invalid user .* <HOST>")

		self.__filter.getFailures(GetFailures.FILENAME_04)

		for output in outputs:
			ticket = self.__filter.failManager.toBan()
			attempts = ticket.getAttempt()
			date = ticket.getTime()
			if not output[-1]:
				output[-1] = date		# cheat cheat cheat for those without years
			ip = ticket.getIP()
			found = (ip, attempts, date)
			self.assertEqual(found, tuple(output))
		# and there should be no more
		self.failUnlessRaises(FailManagerEmpty, self.__filter.failManager.toBan)

	def testGetFailuresMultiRegex(self):
		outputs = (('141.3.81.106', 8, None),
				   # ('66.38.192.238', 1, 1) # we need 3 according to maxRetry
				   )

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_02)

		for ip, attempts, _ in outputs:
			ticket = self.__filter.failManager.toBan()

			attempts = ticket.getAttempt()
			ip = ticket.getIP()

			self.assertEqual(ticket.getIP(), ip)
			self.assertEqual(ticket.getAttempt(), attempts)
			# no time comparison  			date = ticket.getTime()

		# and there should be no more
		self.failUnlessRaises(FailManagerEmpty, self.__filter.failManager.toBan)

	def testGetFailuresIgnoreRegex(self):

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		self.__filter.addIgnoreRegex("for roehl")

		self.__filter.getFailures(GetFailures.FILENAME_02)

		self.assertRaises(FailManagerEmpty, self.__filter.failManager.toBan)
