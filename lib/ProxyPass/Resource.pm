package ProxyPass::Resource;
use Mojo::Base -base, -signatures;

use Mojo::ByteStream qw(b);
use Mojo::File qw(path);
use Mojo::URL;

use constant DEBUG => $ENV{MOJO_PROXY_DEBUG} //= 0;

has no_https => 1;
has [qw(uds uds_path)];

sub base ($self) {
  $self->upstream->clone->path_query($self->downstream->path_query)->tap(sub {$self->_fix_scheme($self->downstream)});
}

sub downstream {
  my $self = shift;
  return $self->{downstream} unless @_;
  $self->{downstream} = shift;
  return $self;
}

sub dump ($self) {
  warn $self->uds if $self->uds;
  warn sprintf "%s => %s\n", $self->downstream, $self->upstream;
}

sub new {
  my $self = shift->SUPER::new;
  if (ref $_[0] eq 'Mojo::File') {
    $self->uds(shift)->uds_path(shift);
    $self->downstream($self->_downstream_uds);
    $self->upstream($self->_upstream_uds);
  }
  else {
    $self->downstream(_url($_[0]));
    $self->upstream(_url($_[1]));
  }
  return $self;
}

sub proxypass ($self, $url) {
  $url = $url->clone;
  my $proxypass = $self->upstream->clone->base($self->base)->path_query($url->path_query)->tap(sub {$self->_fix_scheme($url)});
  warn sprintf "%s => %s\n", $url->to_abs, $proxypass if DEBUG;
  return $proxypass;
}

sub upstream {
  my $self = shift;
  return $self->{upstream} unless @_;
  $self->{upstream} = shift;
  return $self;
}

sub _fix_scheme ($self, $url) {
  $_->scheme($url->to_abs->scheme || 'http') unless $_->scheme;
  $_->{scheme}.='+unix' if $self->uds && $_->{scheme} !~ /\+unix/;
  $_->{scheme} =~ s/https/http/ if $self->no_https;
  return $_;
}

sub _downstream_uds ($self) {
  Mojo::URL->new('//'.path(b($self->uds->to_rel($self->uds_path))->url_unescape))
}

sub _upstream_uds ($self) {
  my $host_port = $self->downstream->host_port;
  my $escaped_path = b($self->downstream->path)->url_escape->to_string;
  my $escaped_uds = b($host_port.$escaped_path)->url_escape->to_string;
  my $escaped_host_port = $self->uds_path->child($escaped_uds);
  $self->downstream->clone->host_port($escaped_host_port);
}

sub _url ($string) {
  $_ = $string;
  Mojo::URL->new(m!://|^//!?$_:"//$_");
}

1;
