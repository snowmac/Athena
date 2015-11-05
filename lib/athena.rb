require 'openssl'
require "base64"

class Athena

  def initialize(options)
    @key = options[:key]
    @encode_as_base64 = options[:encode_as_base64]
  end

  def encrypt(data)
    encrypt = coding('encrypt')
    encrypt = Base64.strict_encode64(encrypt).encode('utf-8') if @encode_as_base64
    encrypt
  rescue StandardError => e
    raise "Could not encrypt the data; following, KEY: #{@key}, #{e.inspect}"
  end

  def decrypt(data)
    decrypt = Base64.strict_decode64(wdata.encode('ascii-8bit'))
    decrypt = coding('decrypt')
    decrypt = Base64.strict_encode64(decrypt).encode('utf-8') if @encode_as_base64
    decrypt
  rescue
    decrypt ## Field was not encrypted
  end

  private

  def coding(type,data)
    raise 'must select between encrypt or decrypt' unless [:encrypt, :decrypt].include? type.to_sym
    instance = OpenSSL::Cipher::AES256.new(:CBC)
    instance.key = @key
    instance.send(type)
    instance.update(data) + instance.final
  end
end
