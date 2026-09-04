require "openssl"
require "bcrypt"

# password hashing — bcrypt (good)
def hash_password(pw)
  BCrypt::Password.create(pw)
end

# session cipher — AES-256-CBC
def encrypt_session(data, key, iv)
  c = OpenSSL::Cipher.new("aes-256-cbc")
  c.encrypt
  c.key = key
  c.iv = iv
  c.update(data) + c.final
end

def token
  SecureRandom.hex(32)
end
