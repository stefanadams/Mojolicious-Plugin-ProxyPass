package Mojolicious::Plugin::RequestBase;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

sub register {
  my ($self, $app, $config) = @_;

  $app->hook(before_dispatch => sub ($c) {
    # Apps behind a reverse proxy should be started with '-p' or MOJO_REVERSE_PROXY
    return unless $c->req->reverse_proxy;

    return unless my $base = $c->req->headers->header('X-Request-Base');
    $c->log->trace("X-Request-Base: $base");

    $base = Mojo::URL->new($base);
    push @{$c->req->url->base->path->trailing_slash(1)},
      splice @{$c->req->url->path->leading_slash(0)}, 0, $base->path->parts->@*
      if $c->req->url->path->contains($base->path->trailing_slash(0));
  });
}

1;