use Mojo::Base -strict, -signatures;

BEGIN { $ENV{MOJO_REACTOR} = 'Mojo::Reactor::Poll' }

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
  $t->get_ok('/size/200/2')->status_is(302);
  $t->get_ok('/proxypass/login')->status_is(200);
  $t->get_ok('/size/200/2')->status_isnt(200);
  $t->get_ok('/proxypass/login?proxypass=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhIiwiZXhwIjoxNjcwODE3NTE2fQ.oIl1alsXTh3-Uag8Q2Nc09V4Tq5EZDpT3bWcDZ4MFbI')->status_is(500);
  $t->get_ok('/size/200/2')->status_isnt(200);
  #$t->get_ok(app->proxy->jwt->jwt_timeout(-1)->url('/proxypass/login', 'a'))->status_is(500);
  #$t->get_ok('/size/200/2')->status_isnt(200);
  $t->get_ok(app->proxy->jwt->url('/proxypass/login', 'a'))->status_is(200);
  $t->get_ok('/size/200/2')->status_is(200);
};

done_testing();
