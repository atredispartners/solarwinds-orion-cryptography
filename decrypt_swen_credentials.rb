#!/usr/bin/env ruby
#
# Decrypt a CSV export of any Solarwinds Orion table with SWEN passwords.
# Copyright (C) 2018 Atredis Partners. MIT License
#

require 'openssl'
require 'base64'

pkey = OpenSSL::PKey::RSA.new(File.read("orion.pem"))
ARGV.each do |fname|
  data = ''
  File.open(fname, "rb") {|fd| data = fd.read}
  data.gsub!("\x00", "")

  replaced = false
  data.gsub!(/\"SWEN_[^\"]+/) do |m|
    prefix, crypted = m.split("__", 2)
    decrypted = '"' + pkey.private_decrypt( crypted.unpack("m*").first ).gsub("\x00", '')
    replaced = true
    decrypted

  end
   
   if replaced
     File.open(fname + ".dec", "wb") do |fd|
       fd.write(data)
     end
   end
end
