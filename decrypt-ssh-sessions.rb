#!/usr/bin/env ruby
#
# Decrypt a CSV export of the Solarwinds Orion SSH_Sessions table
# Copyright (C) 2018 Atredis Partners. MIT License
#

require 'openssl'
require 'base64'

pkey = OpenSSL::PKey::RSA.new(File.read("orion.pem"))
ARGV.each do |fname|
  data = ''
  File.open(fname, "rb") {|fd| data = fd.read}
  data.gsub!("\x00", "")
  data.each_line do |line|
    bits = line.strip.split(",")
    next if bits[0] =~ /ClientId/
    bits = bits.map{|x| x.gsub('"', '') }
    bits[2] = pkey.private_decrypt( bits[2].unpack("m*").first ).gsub("\x00", '')
    bits[3] = pkey.private_decrypt( bits[3].unpack("m*").first ).gsub("\x00", '')
    puts bits.join(",")
  end
end
