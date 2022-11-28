use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::ProxyPass',
  VERSION_FROM => 'lib/Mojolicious/Plugin/ProxyPass.pm',
  AUTHOR       => 'Stefan Adams <sadams@cpan.org>',
  PREREQ_PM    => {'Mojolicious' => '9.20'},
  test         => {TESTS => 't/*.t'}
);
