#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           <��1�.����/��.d�J�@�}8.:y�$F�޼K3����'������O{~��EY�9�8��é(����	���F(���)�WO��G������I�$�]Ґ�dv����_�*�u"""
from hashlib import sha256
if sha256(blob).hexdigest() == 'a500bafc2e20c93c9fee0aa6250a7c08fc8cd027b3376b4e6eb18a28d183fbc7':
	print "I come in peace."
else:
	print "Prepare to be destroyed!"
