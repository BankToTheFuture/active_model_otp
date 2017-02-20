module Devise
  module Models
    module OneTimePassword
      extend ActiveSupport::Concern

      module ClassMethods

        def has_one_time_password(options = {})
          cattr_accessor :otp_column_name, :otp_counter_column_name
          class_attribute :otp_digits, :otp_counter_based

          self.otp_column_name = (options[:column_name] || "otp_secret_key").to_s
          self.otp_digits = options[:length] || 6

          self.otp_counter_based = (options[:counter_based] || false)
          self.otp_counter_column_name = (options[:counter_column_name] || "otp_counter").to_s

          include InstanceMethodsOnActivation
          include EncryptionInstanceMethods if options[:encrypted] == true
          before_create do
            self.otp_regenerate_secret if !otp_column
            self.otp_regenerate_counter if otp_counter_based && !otp_counter
          end

          if respond_to?(:attributes_protected_by_default)
            def self.attributes_protected_by_default #:nodoc:
              super + [otp_column_name, otp_counter_column_name]
            end
          end
        end

        ::Devise::Models.config(self, :otp_secret_encryption_key)
      end

      module InstanceMethodsOnActivation
        def otp_regenerate_secret
          self.otp_column = ROTP::Base32.random_base32
        end

        def otp_regenerate_counter
          self.otp_counter = 1
        end

        def authenticate_otp(code, options = {})
          if otp_counter_based
            hotp = ROTP::HOTP.new(otp_column, digits: otp_digits)
            result = hotp.verify(code, otp_counter)
            if result && options[:auto_increment]
              self.otp_counter += 1
              save if respond_to?(:new_record) && !new_record?
            end
            result
          else
            totp = ROTP::TOTP.new(otp_column, digits: otp_digits)
            if drift = options[:drift]
              totp.verify_with_drift(code, drift)
            else
              totp.verify(code)
            end
          end
        end

        def otp_code(options = {})
          if otp_counter_based
            if options[:auto_increment]
              self.otp_counter += 1
              save if respond_to?(:new_record) && !new_record?
            end
            ROTP::HOTP.new(otp_column, digits: otp_digits).at(self.otp_counter)
          else
            if options.is_a? Hash
              time = options.fetch(:time, Time.now)
              padding = options.fetch(:padding, true)
            else
              time = options
              padding = true
            end
            ROTP::TOTP.new(otp_column, digits: otp_digits).at(time, padding)
          end
        end

        def provisioning_uri(account = nil, options = {})
          account ||= self.email if self.respond_to?(:email)
          account ||= ""

          if otp_counter_based
            ROTP::HOTP.new(otp_column, options).provisioning_uri(account)
          else
            ROTP::TOTP.new(otp_column, options).provisioning_uri(account)
          end
        end

        def otp_column
          self.public_send(self.class.otp_column_name)
        end

        def otp_column=(attr)
          self.public_send("#{self.class.otp_column_name}=", attr)
        end

        def otp_counter
          if self.class.otp_counter_column_name != "otp_counter"
            self.public_send(self.class.otp_counter_column_name)
          else
            super
          end
        end

        def otp_counter=(attr)
          if self.class.otp_counter_column_name != "otp_counter"
            self.public_send("#{self.class.otp_counter_column_name}=", attr)
          else
            super
          end
        end
      end

      module EncryptionInstanceMethods
        def otp_secret_key
            decrypt(encrypted_otp_secret_key) rescue nil
          end
        end

        def otp_secret_key=(value)
          self.encrypted_otp_secret_key = encrypt(value) rescue nil
        end

        private

        def decrypt(encrypted_value)
          return encrypted_value if encrypted_value.blank?

          encrypted_value = encrypted_value.unpack('m').first

          value = ::Encryptor.decrypt(encryption_options_for(encrypted_value))

          if defined?(Encoding)
            encoding = Encoding.default_internal || Encoding.default_external
            value = value.force_encoding(encoding.name)
          end

          value
        end

        def encrypt(value)
          return value if value.blank?

          value = value.to_s
          encrypted_value = ::Encryptor.encrypt(encryption_options_for(value))

          encrypted_value = [encrypted_value].pack('m')

          encrypted_value
        end

        def encryption_options_for(value)
          {
            value: value,
            key: Devise.otp_secret_encryption_key,
            iv: iv_for_attribute,
            salt: salt_for_attribute
          }
        end

        def iv_for_attribute(algorithm = 'aes-256-cbc')
          iv = encrypted_otp_secret_key_iv

          if iv.nil?
            algo = OpenSSL::Cipher::Cipher.new(algorithm)
            iv = [algo.random_iv].pack('m')
            self.encrypted_otp_secret_key_iv = iv
          end

          iv.unpack('m').first if iv.present?
        end

        def salt_for_attribute
          salt = encrypted_otp_secret_key_salt ||
                 self.encrypted_otp_secret_key_salt = generate_random_base64_encoded_salt

          decode_salt_if_encoded(salt)
        end

        def generate_random_base64_encoded_salt
          prefix = '_'
          prefix + [SecureRandom.random_bytes].pack('m')
        end

        def decode_salt_if_encoded(salt)
          salt.slice(0).eql?('_') ? salt.slice(1..-1).unpack('m').first : salt
        end
      end
    end
  end
end
