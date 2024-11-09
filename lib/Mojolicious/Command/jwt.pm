package Mojolicious::Command::jwt;
use Mojo::Base 'Mojolicious::Command';

has description => 'Generate a JWT';
has usage       => sub { shift->extract_usage };

sub run {
  my $self = shift;

  die $self->usage unless @_ >= 2;

  my ($url, $id, $admin, $expires) = @_;
  my $jwt = $self->app->proxy->jwt;
  my $token = $jwt->token($id, $admin, $expires||600);

  say $jwt->url($url, $token);
}

1;

=encoding utf8

=head1 NAME

Mojolicious::Command::jwt - Generate ProxyPass JWT

=head1 SYNOPSIS

  Usage: APPLICATION jwt url username

    mojo jwt http://proxy-url carl [admin] [timeout]

  Options:
    -h, --help   Show this summary of available options

=head1 DESCRIPTION

L<Mojolicious::Command::jwt> generates a ProxyPass JWT for authenticating to the reverse proxy server.

=head1 ATTRIBUTES

L<Mojolicious::Command::jwt> inherits all attributes from L<Mojolicious::Command> and implements the following new
ones.

=head2 description

  my $description = $v->description;
  $v              = $v->description('Foo');

Short description of this command, used for the command list.

=head2 usage

  my $usage = $v->usage;
  $v        = $v->usage('Foo');

Usage information for this command, used for the help screen.

=head1 METHODS

L<Mojolicious::Command::jwt> inherits all methods from L<Mojolicious::Command> and implements the following new
ones.

=head2 run

  $v->run(@ARGV);

Run this command.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<https://mojolicious.org>.

=cut