package ProxyPass;
use Mojo::Base -base, -signatures;

use Mojo::Collection qw(c);
use ProxyPass::Resource;

has [qw(config uds_path)];

has resources => sub ($self) {
  my $uds_path = $self->uds_path;
  my $config_hash = $self->config;
  my $uds = $uds_path ? $uds_path->list->grep(sub{-S})
    ->map(sub {
      ProxyPass::Resource->new($_, $uds_path)
    }) : c;
  my $config = c(keys %$config_hash)
    ->map(sub {
      ProxyPass::Resource->new($_, $config_hash->{$_})
    });
  return c(@$config, @$uds)->sort(\&_sort_resources);
};

sub find ($self, $url) {
  return c() unless $url->to_abs->host_port;
  $self->resources->grep(sub { _grep_url($url->clone) })
  #->tap(sub{$_->dump for @$_})
}

sub _grep_url ($url) {
  return unless $_->downstream->host_port;
  $_->downstream->host_port eq $url->to_abs->host_port &&
  $url->path->trailing_slash(0)->contains($_->downstream->path->trailing_slash(0))
}

sub _sort_resources {
  $b->downstream->host_port cmp $a->downstream->host_port ||
  scalar $b->downstream->path->parts->@* <=> scalar $a->downstream->path->parts->@*
}

1;
