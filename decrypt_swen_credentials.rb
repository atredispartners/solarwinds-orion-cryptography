#!/usr/bin/env ruby

require 'openssl'
require 'base64'

# Exported SolarWinds-Orion Key (local admin)
pkey_txt = %^
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: 20091365-384e-49ae-88fa-6b9766005ef8
    Microsoft CSP Name: Microsoft Enhanced RSA and AES Cryptographic Provider
Key Attributes
    X509v3 Key Usage: 10 
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJ4QB4R3VN9Vhyox
1CB+QyDf8kvYlasEaPqnvhgykd7kedLfXv6X+uVo3W6NG1mjoai7L/HimyJtcmc7
oxTNbqlpcNoAoxYFvBOnFH6R/bzrBwHfrZAuVp8uujYrqw98AN5tbqaumrqQKV5r
9gh2x3v4iD2pKhi2v2dU6WpYRXChAgMBAAECgYAJx6YfbR7EPs+BLdoZNJbEtvaP
+NOx5DD2qWBasO5To0Fiac2/5PlyLl3dFEAH+Nbs0MAzsDi3FZyJhKgfhmJ9Yg+i
iegKr8PjJlgjj4ttOW72Mm7KKeeL/uiAg4iJ6jM4OdaHclYXhkTqrXvXNnzC+KeO
NtkdbXrETQ4o5HXozQJBAM//62S48Snb1SQBfiEaIV+J6Zlho/s7L2cNJ/rQVne0
Mdo88p7glinI0mDbuhOMNsoAjLANhSUZ4z5aqG3/QqsCQQDCifUj/Y0aFnrZ/RnX
CZCBcF2RjPlZsvWncoFnhfirlzS/NmuYLzKU8M6PJF0DdkUHezMQAfsBMDsOQh5d
P/njAkBIYmBxyearUYSIJjjVnjlU/TKdHRyq9nrVmv95ynz85Wmf8Cvi3HeFjQyh
hnXoDZiXjb9oGRxnv+2UKoqI1RdHAkBIXb9mGvyxNqmOi5tgJbuumtkDuthK6Mp+
9pZypyCA3CeP9bOCkhQT2ZxNHS7IiedVyBuPmd0AbSuauzfGYnUXAkB9InxQXga+
pkTGVjXY1K0jDHh/zWrMZz7dCZfvQQHL5xF3hPYRMcnIGld41VSydM4rR2gcj396
lqP8uMlJ+p3X
-----END PRIVATE KEY-----
Bag Attributes
    localKeyID: 01 00 00 00 
    1.3.6.1.4.1.311.17.3.20: B4 EB 50 F8 01 FB EA BC 08 ED 2F 62 DC 5C 2B EB CF 75 31 11 
    friendlyName: SolarWinds-Orion
subject=/CN=SolarWinds-Orion
issuer=/CN=SolarWinds-Orion
-----BEGIN CERTIFICATE-----
MIICIjCCAYugAwIBAgIQ3XCi7gQfxKtEjrZMnUVzdjANBgkqhkiG9w0BAQUFADAb
MRkwFwYDVQQDDBBTb2xhcldpbmRzLU9yaW9uMB4XDTEwMDUxMjE1MzQ0N1oXDTM5
MTIzMTE3NTk1OVowGzEZMBcGA1UEAwwQU29sYXJXaW5kcy1PcmlvbjCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEAnhAHhHdU31WHKjHUIH5DIN/yS9iVqwRo+qe+
GDKR3uR50t9e/pf65Wjdbo0bWaOhqLsv8eKbIm1yZzujFM1uqWlw2gCjFgW8E6cU
fpH9vOsHAd+tkC5Wny66NiurD3wA3m1upq6aupApXmv2CHbHe/iIPakqGLa/Z1Tp
alhFcKECAwEAAaNnMGUwTgYDVR0jBEcwRYAQKg5lERdC9oG55tkPeMKJcaEfpB0w
GzEZMBcGA1UEAwwQU29sYXJXaW5kcy1PcmlvboIQ3XCi7gQfxKtEjrZMnUVzdjAT
BgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQUFAAOBgQAL8drImwoGZxHR
wYX1P5Anf1180PHEv9Yl7ZKNb7x7VG7NrLcHfpD3x8qqwJxidWY0pNsoEi6X+gu9
3+FUEnt2y34c68p5klr0NPqCKMuCxSRPA5M5xbrc9Cq268zwmAe4UN8qfK9Oi4sM
lCJjKJZVsVaR9WN1YtSx0Ax+A5idYA==
-----END CERTIFICATE-----
^

pkey = OpenSSL::PKey::RSA.new(pkey_txt)
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
