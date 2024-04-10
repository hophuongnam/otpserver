#!/usr/bin/ruby
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004
#
# Copyright (C) 2021 Ho Phuong Nam <hophuongnam@gmail.com>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.

# REDIS keys:
# username => otp key
# username_token => token
# username_email => email address
# username_nootp => 1 (this key exists to signify that this user is not eligible to OTP authen)
# username_attributes => additional RADIUS attributes

require 'redis'
require 'json'
require 'rpam2'
require 'sinatra'
require 'mail'
require 'net/http'
require 'rack/throttle'
require 'rotp'

sentinel  = Hash.new
sentinels = Array.new
config = YAML.load(File.read('/etc/freeradius/3.0/config.otp.yaml')).transform_keys(&:to_sym)
smtp = config[:smtp].transform_keys(&:to_sym)

config[:sentinels].each do |key, value|
  sentinel[:host] = key
  sentinel[:port] = value
  sentinels << sentinel
  sentinel = {}
end

redis = Redis.new(url: 'redis://mymaster', sentinels: sentinels, role: :master, password: config[:rpass], sentinel_password: config[:spass])

# 1 request every 2s
# Frond End will have to check for code 403
# use Rack::Throttle::Interval, :cache => redis_throttle, :key_prefix => :throttle, :min => 2.0
rules = [
  { method: "POST", limit: 2 },
  { method: "POST", path: "/authen", whitelisted: true }
]
ip_whitelist = ["127.0.0.1"]
use Rack::Throttle::Rules, rules: rules, ip_whitelist: ip_whitelist

Mail.defaults do
  delivery_method :smtp, address: smtp[:address], port: smtp[:port]
end

before do
  content_type :JSON
end

CHARS = ('0'..'9').to_a
def random_token(length=6)
  CHARS.sort_by { rand }.join[0...length]
end

post '/gettoken' do
  real_ip = request.env["HTTP_X_REAL_IP"]
  # puts request.env["HTTP_X_REAL_IP"]
  # Check username and password
  params = JSON.parse(request.body.read).transform_keys(&:to_sym)
  username = params[:username].split('@')[0]
  username.downcase!
  password = params[:password]

  if Rpam2.auth("otp", username, password)
    # puts "Authentication successful"
    token = random_token
    redis.set "#{username}_token", token
    redis.expire "#{username}_token", 600

    # email token to user
    mail_body = <<~BODY.strip
      Hello #{username},<br><br>
      You or someone request an authentication token to access OTP Provisioning page from IP #{request.env["HTTP_X_REAL_IP"]}.<br>
      Anyway, this is your token:
      <h1>#{token}</h1>

      Regards,<br>
      Security Team.
    BODY

    # check if username begins with "pam."
    # if so, remove it
    username.delete_prefix! "pam."

    # user's email address
    email_address = redis.get "#{username}_email"
    email_address = "#{username}@#{config[:email_domain]}" if email_address.nil?

    Mail.deliver do
      from    config[:sender_address]
      to      "#{email_address}"
      subject "(#{Time.now.strftime "%d/%m/%Y %I:%M %p"}) Your token"

      html_part do
        content_type 'text/html; charset=UTF-8'
        body mail_body
      end
    end
    return {
      message: "Token generated and email to #{email_address}",
      status: "success"
    }.to_json
  else
    puts "Authentication failed for #{username}"
    return {
      message: "Error, check your username or password!",
      status: "warning"
    }.to_json
  end
end

post '/getotp' do
  params = JSON.parse(request.body.read).transform_keys(&:to_sym)
  username = params[:username].split('@')[0]
  username.downcase!
  password = params[:password]
  token = params[:token]
  reset = params[:reset]

  # check token first
  current_token = redis.get "#{username}_token"
  if current_token.nil?
    return {
      message: "Token not found!",
      status: "warning"
    }.to_json
  end

  if token.to_i == current_token.to_i
    if Rpam2.auth("otp", username, password)
      current_key = redis.get username
      if current_key.nil? or reset == "yes"
        current_key = ROTP::Base32.random_base32.upcase
        redis.set username, current_key
      end

      totp = ROTP::TOTP.new current_key
      uri = totp.provisioning_uri "FPTCloud Inside:#{username}"
      uri.sub! "_", ":"

      return {
        message: "Success, your OTP key is displayed below",
        uri: uri,
        key: current_key,
        time: Time.now.to_i,
        status: "success"
      }.to_json
    else
      # Authentication failed
      return {
        message: "Error, check your username or password!",
        status: "warning"
      }.to_json
    end
  else
    # token mismatch
    return {
      message: "Wrong token!",
      status: "warning"
    }.to_json
  end
end

post '/authen' do
  params = JSON.parse(request.body.read).transform_keys(&:to_sym)
  username = params[:username].split('@')[0]
  username.downcase!
  password = params[:password]

  if Rpam2.auth("otp", username, password)
    return {
      message: "Authentication Success",
      status: true
    }.to_json
  else
    return {
      message: "Authentication Failed",
      status: false
    }.to_json
  end
end

get '/' do
  content_type :html
  send_file "/etc/freeradius/3.0/otp/otp.html"
end
