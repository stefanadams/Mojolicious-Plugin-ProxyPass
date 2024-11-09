#!/usr/bin/env perl

use Mojolicious::Lite -signatures;

app->session->default_expiration(86_400 * 365);

plugin 'ProxyPass' => {
  auth_upstream => ['127.0.0.1:3001'],
  uds_path => '',
  upstream => {
    '127.0.0.1' => '127.0.0.1:3001', # requires auth
    '127.0.0.2' => '127.0.0.1:3002', # does not require auth
  },
};

# Alternative authentication to built-in JWT
app->helper('proxy.login' => sub ($c) {
  my $username = $c->param('username');
  my $password = $c->param('password');
  return unless $username && $password;
  return $username if $username eq 'a' && $password eq 'a';
});

app->proxy->pass(
  sub ($c, $or_tx) { # Request
    $or_tx->req->headers->user_agent('MojoProxy/1.0');
  },
  # sub ($c, $or_tx) { # Response
  # },
  # Mojo::Collection->new( # Filter/Intercept
  #   [
  #     sub ($c, $or_tx) {}, # Filter
  #     sub ($c, $up_tx) {}, # Intercept
  #   ],
  #   ...
  # )
);

app->start;
