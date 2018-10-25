#!/usr/bin/env ruby
#
# Generate a password hash for the Accounts table of SolarWinds Orion
# Copyright (C) 2018 Atredis Partners. MIT License
#

require 'openssl'
require 'base64'
require 'digest'

def usage
  $stderr.puts "#{$0} <username> <password>"
  exit(1)
end

username = ARGV.shift || usage()
password = ARGV.shift || usage()
padding  = "1244352345234"

salt = username.downcase
if salt.length < 8 
  salt = salt + padding[0, 8-salt.length]
end

pbkdf2 = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, 1000, 1024)
sha512 = [ Digest::SHA2.new(512).digest(pbkdf2) ].pack("m*").gsub(/\s+/, '')
$stdout.puts "User '#{username}' with password '#{password}' has hash '#{sha512}'"

=begin
    # Extract from SolarWinds.Orion.Core.Common.dll HashPassword()
    public static string HashPassword(string password, string salt, bool caseSensitive)
    {
      if (password == null)
      {
        throw new ArgumentException("password");
      }
      if (salt == null)
      {
        throw new ArgumentException("salt");
      }
      HashAlgorithm hashAlgorithm = new SHA512CryptoServiceProvider();
      string password2 = password;
      if (!caseSensitive)
      {
        password2 = password.ToUpperInvariant();
      }
      Encoding encoding = new UTF8Encoding();
      int length = salt.ToLowerInvariant().Length;
      byte[] bytes = encoding.GetBytes(salt.ToLowerInvariant() + ((length < 8) ? "1244352345234".Substring(0, 8 - length) : ""));
      string result;
      using (DeriveBytes deriveBytesAlgorithm = EncryptionHelper.GetDeriveBytesAlgorithm(password2, bytes))
      {
        result = Convert.ToBase64String(hashAlgorithm.ComputeHash(deriveBytesAlgorithm.GetBytes(EncryptionHelper.BytesUsedForHash)));
      }
      return result;
    }
=end