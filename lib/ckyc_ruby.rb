require "ckyc_ruby/version"
require 'rest-client'
require 'json'
require 'active_support/core_ext/hash'
require 'base64'

module CkycRuby
  class Error < StandardError; 

    PRIVATE_KEY_ERROR = "Couldn't locate private key"
    PUBLIC_CKYC_KEY_ERROR = "Couldn't locate public key"

  end
  class Ckyc
  	
  	def initialize url:  , private_key: , fi_code:, public_ckyc_key:  
      raise CkycRuby::Error::PRIVATE_KEY_ERROR unless File.file?(private_key)
      raise CkycRuby::Error::PUBLIC_CKYC_KEY_ERROR unless File.file?(public_ckyc_key)
  		@url, @fi_code,@private_key,@public_ckyc_key  = url , fi_code, private_key, public_ckyc_key
      
  	end

  	def check_ckyc pan: , dob: 
  		@pan,@dob = pan,dob
  		xml = check_xml 
      begin
  		  response = RestClient.post @url,{xml: Base64.urlsafe_encode64(xml),request_type: "1"}.to_json , {"Content-Type" => "application/json"}
      rescue
        return {status: "failure", reason: "Couldn't connect to ckyc server"}
      else
        parsed = parse_response(response.body)

        parsed = Nokogiri::XML(parsed)
        if parsed.at_xpath('//ERROR').nil?
          ret  = Hash.from_xml(parsed.to_s)
          ret[:status] = "success"
          return ret
        else
          { status: "failure",
            reason: parsed.at_xpath('//ERROR').content,
          }
        end
      end
  	end

    def download auth_factor_type: , auth_factor:  , ckyc_no: 
      @auth_factor_type, @auth_factor , @ckyc_no = auth_factor_type , auth_factor  , ckyc_no
      xml = download_xml
      begin

        response =  RestClient.post @url,{xml: Base64.urlsafe_encode64(xml),request_type: "2"}.to_json , {"Content-Type" => "application/json"}
        rescue
          return {status: "failure", reason: "Couldn't connect to ckyc server"}
        else
          parsed = parse_response(response.body)
          parsed = Nokogiri::XML(parsed)
          if parsed.at_xpath('//ERROR').nil?
            ret  = Hash.from_xml(parsed.to_s)
            ret[:status] = "success"
            return ret 
          else
            { status: "failure",
              reason: parsed.at_xpath('//ERROR').content,
            }
          end
        end
    end


  	private 


  	def sessionKey
      OpenSSL::Random.random_bytes(32)
  	end

  	def check_xml 
  		session = sessionKey 
  		@enc_session = encr_sess_key session
  		pid = check_xml_pid
  		@encr_pid = encrPidString pid , session
  		check_xml_final
  	end

  	def check_xml_pid
  		x = Nokogiri::XML::Builder.new(:encoding => 'UTF-8') do |xml|
			xml.PID_DATA {
			    xml.DATE_TIME Time.now.strftime("%d-%m-%Y %H:%M:%S")
			    xml.ID_TYPE "C" 
			    xml.ID_NO @pan
			    xml.DOB @dob
			}
		end
		x.to_xml.split.join(" ")
  	end

  	def check_xml_final
  		x = Nokogiri::XML::Builder.new do |xml|
			xml.REQ_ROOT {
				xml.HEADER{
					xml.FI_CODE @fi_code
					xml.REQUEST_ID rand(100000..999999)
					xml.VERSION "1.1"
				}
				xml.CKYC_INQ{
					xml.PID @encr_pid
					xml.SESSION_KEY @enc_session
				}
			}
		end
		x.to_xml.split.join(" ")
  	end

    def download_xml 
      session = sessionKey
      @enc_download_session = encr_sess_key session 
      pid = download_xml_pid 
      @encr_download_pid = encrPidString pid , session
      download_xml_final
    end

    def download_xml_pid 
      x = Nokogiri::XML::Builder.new(:encoding => 'UTF-8') do |xml|
      xml.PID_DATA {
          xml.DATE_TIME Time.now.strftime("%d-%m-%Y %H:%M:%S")
          xml.CKYC_NO @ckyc_no
          xml.AUTH_FACTOR_TYPE @auth_factor_type
          xml.AUTH_FACTOR @auth_factor
      }
      end
      x.to_xml.split.join(" ")
    end

    def download_xml_final 
      x = Nokogiri::XML::Builder.new do |xml|
      xml.CKYC_DOWNLOAD_REQUEST {
        xml.HEADER{
          xml.FI_CODE @fi_code
          xml.REQUEST_ID rand(100000..999999)
          xml.VERSION "1.1"
        }
        xml.CKYC_INQ{
          xml.PID @encr_download_pid
          xml.SESSION_KEY @enc_download_session
        }
      }
    end
      return x.to_xml.split.join(" ")
    end

  	def encrPidString pid , sessionKey
  		cipher = OpenSSL::Cipher.new('AES-256-ECB')
  		cipher.encrypt
  		cipher.key = sessionKey
  		encrypted = cipher.update(pid) + cipher.final
  		Base64.urlsafe_encode64(encrypted)
  	end

  	def encr_sess_key session
		  Base64.encode64(OpenSSL::PKey::RSA.new(File.read @public_ckyc_key).public_encrypt(session,OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING))
  	end

    def parse_response xml 
      doc = Nokogiri::XML(xml)
      if !doc.at_xpath('//ERROR').nil?
        xml
      else
        decode_response doc.at_xpath('//SESSION_KEY').content,doc.at_xpath('//PID').content 
      end
    end

    def decode_response enc_session , enc_pid
      private_key = OpenSSL::PKey::RSA.new(File.read @private_key)
      decr_session = private_key.private_decrypt(Base64.decode64(enc_session),OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      decoded_pid = Base64.decode64(enc_pid)
      cipher = OpenSSL::Cipher.new('AES-256-ECB')
      cipher.decrypt 
      cipher.key = decr_session
      pid_xml = cipher.update(decoded_pid) + cipher.final
    end
  end
end
