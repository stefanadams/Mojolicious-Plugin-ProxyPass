use Mojo::Base -strict, -signatures;

BEGIN {
  $ENV{MOJO_REACTOR} = 'Mojo::Reactor::Poll';
  $ENV{PROXYPASS_DEBUG} //= 0;
  $ENV{PROXYPASS_LOG_LEVEL} //= 'info';
}

use Test::More;
use Test::Mojo;
use Mojolicious::Lite -signatures;

my $t = Test::Mojo->new;

plugin 'ProxyPass';

app->proxy->pass;
get '/*whatever' => sub ($c) {
  return $c->render(text => $c->stash('proxy.error'), status => 404) if $c->stash('proxy.error');
  $c->render(text => 'ok');
};

subtest 'Upstream Missing' => sub {
  $t->get_ok('/size/200/2')->status_is(404)->header_isnt('X-Mojo-App' => 'Size')->content_like(qr(configuration for upstream 127.0.0.1:\d+ not found), 'upstream not found');
};

done_testing();
