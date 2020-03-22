# CkycRuby

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/ckyc_ruby`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ckyc_ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ckyc_ruby

## Usage

```ruby 
foo = CkycRuby::Ckyc.new(url: url , private_key: path_to_private_key, public_ckyc_key: path_to_public_key, fi_code: fi_code)

foo.check_kyc(pan: pan, dob: dob)
foo.download(auth_factor_type: "01",auth_factor: dob, ckyc_no:ckyc_no)
```

returns json with keys status. if status  == error , then there is an error reason . Otherwise, parsed error would be returned. 

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/ckyc_ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
