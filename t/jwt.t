package Test::MockTime;
our $offset = 0;
BEGIN {
  *CORE::GLOBAL::time = \&Test::MockTime::time;
  $ENV{MOJO_REACTOR} = 'Mojo::Reactor::Poll';
  $ENV{PROXYPASS_DEBUG} //= 0;
  $ENV{PROXYPASS_LOG_LEVEL} //= 'info';
}
sub time() { return ( CORE::time + $offset ) }
sub set_relative_time { return $offset = $_[-1] };

package main;
use Mojo::Base -strict, -signatures;

BEGIN {
  $ENV{MOJO_LOG_LEVEL} = 'error';
  $ENV{MOJO_REACTOR}  = 'Mojo::Reactor::Poll';
}

use Test::More;
use Test::Mojo;

use Mojo::Server::Daemon;
use Mojo::URL;
use Mojo::Util qw(url_escape);
use Mojolicious;
use Mojolicious::Lite -signatures;

# Test server with various response variants
my $or_app   = Mojolicious->new;
my $origin   = Mojo::Server::Daemon->new(listen => ['http://127.0.0.2'], silent => 1, app => $or_app);
my $or_port  = $origin->start->ports->[0];
my $or_url   = Mojo::URL->new("http://127.0.0.2:$or_port")->to_abs;
my $or_r     = $or_app->routes;
my $size     = Mojolicious::Routes::Pattern->new('/size/:code2/:length/:extra')->defaults({code2 => 204, length => 0, extra => ''});
my $redirect = Mojolicious::Routes::Pattern->new('/redirect/:code1/:code2/:length/:extra')->defaults({code1 => 302, code2 => 204, length => 0, extra => ''});

$or_r->get('/*all' => {all=>''} => sub ($c) {
  my $captures;
  if ($captures = $size->match($c->req->url->path)) {
    my $code   = $captures->{code2};
    my $length = $captures->{length};
    my $extra  = $captures->{extra};
    $c->res->headers->header('X-Mojo-App'   => 'Size');
    $c->res->headers->header('X-Mojo-Extra' => $extra) if $extra;
    $c->render(data => 'x'x$length, status => $code);
  }
  elsif ($captures = $redirect->match($c->req->url->path)) {
    my $code1  = $captures->{code1};
    my $code2  = $captures->{code2};
    my $length = $captures->{length};
    my $extra  = $captures->{extra};
    $c->res->headers->header('X-Mojo-App'   => 'Redirect');
    $c->res->headers->header('X-Mojo-Extra' => $extra) if $extra;
    $c->res->headers->location(sprintf '%s://%s/size/%s', $c->req->headers->header('X-Forwarded-Proto'), $c->req->url->to_abs->host_port, join '/', grep {length} $code2, $length, $extra);
    $c->rendered($code1);
  }
  else {
    $c->render(text => $c->req->url->path, status => 200);
  }
});

my $t = Test::Mojo->new;
$t->app->log->path('/dev/null');
my $gw_url = $t->ua->server->url->to_abs;

plugin 'ProxyPass' => {
  auth_upstream => [$or_url->host_port],
  upstream => {
    $gw_url->host_port => $or_url->host_port,
  },
};

app->helper('proxy.login' => sub ($c) {
  my $jwt = $c->param('proxypass') or return;
  return $c->proxy->jwt->id($jwt);
});

app->proxy->pass;

subtest 'Various response variants' => sub {
  $t->get_ok('/size/200/2')->status_is(302, 'requires login');
  $t->get_ok('/proxypass/login')->status_is(200, 'redirected to login');
  $t->get_ok('/size/200/2')->status_isnt(200, 'requires login');
  $t->get_ok('/proxypass/login?proxypass=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhIiwiZXhwIjoxNjcwODE3NTE2fQ.oIl1alsXTh3-Uag8Q2Nc09V4Tq5EZDpT3bWcDZ4MFbI')->status_is(500, 'failed HS validation');
  $t->get_ok('/size/200/2')->status_isnt(200, 'requires login');

  my $token = app->proxy->jwt->token('a');
  my $expires = app->proxy->jwt->jwt->decode($token)->{exp};
  my $url = app->proxy->jwt->url('/proxypass/login', $token);

  ok time < $expires, 'time is not expired';
  $t->get_ok($url)->status_is(200, 'logged in');
  $t->get_ok('/size/200/2')->status_is(200, 'got proxied page');

  $t->reset_session and Test::MockTime::set_relative_time(610);
  is time - CORE::time, 610, '"slept" 610 seconds';

  ok time > $expires, 'time is expired';
  $t->get_ok($url)->status_is(500, 'JWT has expired (after mocked time adjustment)');
  $t->get_ok('/size/200/2')->status_is(302, 'requires login');
};

done_testing();
