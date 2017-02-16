require "active_model"
require "active_support/core_ext/module/attribute_accessors"
require "cgi"
require "rotp"
require "active_model/one_time_password"
require 'devise'
require 'encryptor'

# ActiveSupport.on_load(:active_record) do
#   include ActiveModel::OneTimePassword
# end

module Devise
  mattr_accessor :otp_secret_encryption_key
  @@otp_secret_encryption_key = ''
end

Devise.add_module :one_time_password, model: 'active_model/one_time_password'
