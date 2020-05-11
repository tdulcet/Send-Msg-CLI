#[ \"\" ], // The empty string shouldn't be considered as invalid.
values = [
  [ "foo@bar.com"],
  [ " foo@bar.com"],
  [ "foo@bar.com "],
  [ "\r\n foo@bar.com"],
  [ "foo@bar.com \n\r"],
  [ "\n\n \r\rfoo@bar.com\n\n   \r\r"],
  [ "\n\r \n\rfoo@bar.com\n\r   \n\r"],
  [ "tulip"],

  [ "@bar.com"],
  [ "f\noo@bar.com"],
  [ "f\roo@bar.com"],
  [ "f\r\noo@bar.com"],
  [ "fü@foo.com"],

  [ "foo@bar"],
  [ "foo@b"],
  [ "foo@"],
  [ "foo@bar."],
  [ "foo@foo.bar"],
  [ "foo@foo..bar"],
  [ "foo@.bar"],
  [ "foo@tulip.foo.bar"],
  [ "foo@tulip.foo-bar"],
  [ "foo@1.2"],
  [ "foo@127.0.0.1"],
  [ "foo@1.2.3"],
  [ "foo@b\nar.com"],
  [ "foo@b\rar.com"],
  [ "foo@b\r\nar.com"],
  [ "foo@."],
  [ "foo@fü.com"],
  [ "foo@fu.cüm"],
  [ "thisUsernameIsLongerThanSixtyThreeCharactersInLengthRightAboutNow@mozilla.tld"],

  [ "this.is.email.should.be.longer.than.sixty.four.characters.föö@mözillä.tld"],
  [ "this-is-email-should-be-longer-than-sixty-four-characters-föö@mözillä.tld"],

  [ "foo@thislabelisexactly63characterssssssssssssssssssssssssssssssssss"],
  [ "foo@thislabelisexactly63characterssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thislabelisexactly63characterssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thislabelisexactly63characterssssssssssssssssssssssssssssssssss"],
  [ "foo@thislabelisexactly64charactersssssssssssssssssssssssssssssssssss"],
  [ "foo@thislabelisexactly64charactersssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thislabelisexactly64charactersssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thislabelisexactly64charactersssssssssssssssssssssssssssssssssss"],

  [ "foo@thisläbelisexäctly63charäcterssssssssssssssssssssssssssssssssss"],
  [ "foo@thisläbelisexäctly63charäcterssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thisläbelisexäctly63charäcterssssssssssssssssssssssssssssssssss.com"],
  [ "foo@foo.thisläbelisexäctly63charäcterssssssssssssssssssssssssssssssssss"],

  [ "foo@foo-bar"],
  [ "foo@-foo"],
  [ "foo@foo-.bar"],
  [ "foo@-.-"],
  [ "foo@fo-o.bar"],
  [ "foo@fo-o.-bar"],
  [ "foo@fo-o.bar-"],
  [ "foo@fo-o.-"],
  [ "foo@fo--o"],
]
for i in values:
    print(str(i).lstrip('[\'').rstrip('\']'))


  #// Some checks on the user part of the address.
  #// Some checks for the domain part.
  #// Long strings with UTF-8 in username.
  #// Long labels (labels greater than 63 chars long are not allowed).
  #// Long labels with UTF-8 (punycode encoding will increase the label to more than 63 chars).
  #// The domains labels (sub-domains or tld) can"t start or finish with a "-'
