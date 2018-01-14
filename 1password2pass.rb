#!/usr/bin/env ruby

require 'English'
require 'domainatrix'
require 'ipaddress'
require 'json'
require 'optparse'
require 'ostruct'
require 'pry'

# 1Password export file extension.
EXT_PIF = '.1pif'.freeze

# Field identifiers used by 1Password
FIELD_PASSNAME = 'password'.freeze
FIELD_USERNAME = 'username'.freeze

# The command to insert a new pass entry.
PASS_INSERT_CMD = 'gopass insert'.freeze

# The default directory for the password store.
PASS_STORE_DIR = '~/.password-store'.freeze

##
# Extracts a Pass entry title from the provided +url+. Note that this URL may
# also be an IP address, in which case this function is a no-op.
# Params
# +url+:: URL string extracted from the 1Password record.
def get_title_from_url(url)
  return url if IPAddress.valid? url

  parsed_url = Domainatrix.parse(url)
  "#{parsed_url.domain}.#{parsed_url.public_suffix}"
end

# Default options.
options = OpenStruct.new
options.force = false
options.parallel = false

optparse = OptionParser.new do |opts|
  opts.banner = "Usage: #{opts.program_name}.rb [options] filename"

  opts.on_tail('-h', '--help', 'Display this screen') do
    puts opts
    exit
  end

  opts.on('-p', '--parallel', 'Run in multiple threads.') do
    options.parallel = true
  end

  opts.on('-f', '--force', 'Overwrite existing passwords') do
    options.force = true
  end

  begin
    opts.parse!
  rescue OptionParser::InvalidOption
    warn optparse
    exit
  end
end

filename = ARGV.pop
abort optparse.to_s unless filename

file_ext = File.extname(filename.downcase)
abort 'Unsupported file format.' unless file_ext == EXT_PIF

# 1PIF is almost JSON, but not quite. Remove the ***...*** lines separating
# records, and then remove the trailing comma.
pif = File.open(filename).read.gsub(/^\*\*\*.*\*\*\*$/, ',').chomp.chomp(',')

passwords = []
JSON.parse("[#{pif}]", symbolize_names: true).each do |entry|
  # TODO(kenlimmj): (Go)Pass supports binary data, and so should this.
  next unless entry[:typeName] == 'webforms.WebForm'

  fields = entry[:secureContents][:fields]
  next if fields.nil?

  password = fields.detect { |field| field[:designation] == FIELD_PASSWORD }
  next if password.nil? || password.empty?

  pass = { password: password[:value] }

  urls = entry[:secureContents][:URLs]
  if urls.nil? || urls.empty?
    pass[:title] = entry[:title]
  else
    domains = urls.map { |url_entry| get_title_from_url(url_entry[:url]) }.uniq
    pass[:title] = domains[0]

    # If there are multiple domains, we have to prepare to create symlinked
    # entries so they work well with Browserpass-like lookups.
    pass[:symlinks] = domains.drop(1) if domains.length > 1
  end

  # Browserpass uses a YAML index of {domain}/{username} for matching against
  # webpages. Thus if we have a username, we tack it on to the name field.
  username = fields.detect { |field| field[:designation] == FIELD_USERNAME }
  unless username.nil? || username.empty?
    pass[:username] = username[:value]
    pass[:title] += "/#{pass[:username]}"
  end

  passwords << pass
end

puts "Read #{passwords.length} passwords."

errors = []

# TODO(kenlimmj): This can take some time if there are many passwords. Consider
# parallelizing the loop if we know that pass is thread-safe.
passwords.each do |pass|
  next unless pass[:password]

  command =
    "#{PASS_INSERT_CMD}#{' -f' if options.force} -m #{pass[:title]} > /dev/null"
  IO.popen(command, 'w') do |io|
    io.puts pass[:password]
  end

  symlinks = pass[:symlinks]
  unless symlinks.nil? || symlinks.empty?
    target = "$#{PASS_STORE_DIR}/#{pass[:title]}"

    symlinks.each do |url|
      link = "$#{PASS_STORE_DIR}/#{url}"
      link += "/#{pass[:username]}" unless pass[:username].nil?
      FileUtils.ln_sf target, link
    end
  end

  if $CHILD_STATUS.success?
    puts "Imported #{pass[:title]}"
  else
    warn "ERROR: Failed to import #{pass[:title]}"
    errors << pass
  end
end

unless errors.empty?
  warn "Failed to import #{errors.map { |e| e[:title] }.join ', '}"
  warn 'Check the errors. Make sure these passwords do not already '\
    "exist. If you're sure you want to overwrite them with the "\
    'new import, try again with --force.'
end
