#!/usr/bin/env ruby

require 'openssl'
require 'socket'

if ARGV.size != 1
  $stderr.puts "Usage : #{__FILE__} server_cert|server_url"
  exit 1
end

server_cert = nil
if File.exist?(ARGV[0]) then
  server_cert =  OpenSSL::X509::Certificate.new(File.read(ARGV[0]))
else
  server = URI.parse(ARGV[0])
  socket = TCPSocket.new(server.host, server.port)
  ssl_socket = OpenSSL::SSL::SSLSocket.new(socket)
  ssl_socket.connect
  server_cert = ssl_socket.peer_cert
end

key = nil
Dir['id_*.key'].each do |key_file|

  if ( key_file.index('id_rsa') ) then
    key = OpenSSL::PKey::RSA.new(File.read(key_file))
  else
    key = OpenSSL::PKey::DSA.new(File.read(key_file))
  end


  if key.public_key.to_pem == server_cert.public_key.to_pem then
    puts "#{key_file} is the private key associated to the certificate #{ARGV[0]}"
    exit 1
  end
end

puts "No match found :/"
puts "Are you sure you are using the good certificate ?"
