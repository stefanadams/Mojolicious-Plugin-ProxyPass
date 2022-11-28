#!/usr/bin/env perl

use Mojolicious::Lite -signatures;

plugin 'ProxyPass' => {
  auth_upstream => ['127.0.0.1:3001'],
  uds_path => '',
  upstream => {
    '127.0.0.1' => '127.0.0.1:3001',
    '127.0.0.2' => '127.0.0.1:3002',
  },
};

app->helper('proxy.login' => sub ($c) {
  my $username = $c->param('username');
  my $password = $c->param('password');
  return unless $username && $password;
  return $username if $username eq 'a' && $password eq 'a';
});

app->proxy->pass(
  sub ($or_tx) {
    $or_tx->req->headers->user_agent('MojoProxy/1.0');
  },
  sub ($or_tx) {
  },
);

app->start;
