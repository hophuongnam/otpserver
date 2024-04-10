require "rpam2"

if Rpam2.auth("otp", "username", "password")
  puts "OK"
else
  puts "Failed"
end
