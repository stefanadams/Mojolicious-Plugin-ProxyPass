use Mojo::Base -strict, -signatures;

BEGIN {
  $ENV{MOJO_REACTOR} = 'Mojo::Reactor::Poll';
  $ENV{PROXYPASS_DEBUG} //= 0;
  $ENV{PROXYPASS_LOG_LEVEL} //= 'info';
}

use Test::More;
use Test::Mojo;

use Mojo::ByteStream qw(b);
use Mojo::File qw(tempdir);
use Mojo::URL;

my $tempdir = tempdir;
my $sockdir = b($tempdir)->url_escape;
my $socket1 = b($tempdir->child('hello_world'))->url_escape;
my $socket2 = b($tempdir->child('hello_world%2Fc'))->url_escape;
my $socket3 = b($tempdir->child('hello_world%2Fc%2Fd'))->url_escape;
my $socket4 = b($tempdir->child('127.0.2.1'))->url_escape;
my $socket5 = b($tempdir->child('127.0.2.1%2Fc'))->url_escape;
my $socket6 = b($tempdir->child('127.0.2.1%2Fc%2Fd'))->url_escape;
my $t = Test::Mojo->new('Mojo::HelloWorld');
my $tcp1 = Mojo::Server::Daemon->new(listen => ["http://127.1.2.3:7123"], silent => 1, app => $t->app)->start;
my $tcp2 = Mojo::Server::Daemon->new(listen => ["http://127.1.2.4:7124"], silent => 1, app => $t->app)->start;
my $tcp3 = Mojo::Server::Daemon->new(listen => ["http://127.1.2.5:7125"], silent => 1, app => $t->app)->start;
my $uds1 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket1"], silent => 1, app => $t->app)->start;
my $uds2 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket2"], silent => 1, app => $t->app)->start;
my $uds3 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket3"], silent => 1, app => $t->app)->start;
my $uds4 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket4"], silent => 1, app => $t->app)->start;
my $uds5 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket5"], silent => 1, app => $t->app)->start;
my $uds6 = Mojo::Server::Daemon->new(listen => ["http+unix://$socket6"], silent => 1, app => $t->app)->start;
$t->app->plugin('ProxyPass' => {
  uds_path => $tempdir,
  upstream => {
    '127.0.0.1'          => '127.1.1.0',
    '127.0.0.1/a'        => '127.1.1.1',
    '127.0.0.1/a/b'      => '127.1.1.2',
    '127.0.0.1:3000'     => '127.1.1.3',
    '127.0.0.1:3000/a'   => '127.1.1.4',
    '127.0.0.1:3000/a/b' => '127.1.1.5',
    '127.0.0.1:4000'     => '127.1.2.3:7123',
    '127.0.0.1:4000/a'   => '127.1.2.4:7124',
    '127.0.0.1:4000/a/b' => '127.1.2.5:7125',
    '127.0.1.1'          => "http+unix://$socket1",
    '127.0.1.1/c'        => "http+unix://$socket2",
    '127.0.1.1/c/d'      => "http+unix://$socket3",
  },
});

my %tests = (
  '//127.0.0.1'            => ['http://127.1.1.0', 'http://127.1.1.0'],
  '//127.0.0.1/a'          => ['http://127.1.1.1/a', 'http://127.1.1.1/a'],
  '//127.0.0.1/a/b'        => ['http://127.1.1.2/a/b', 'http://127.1.1.2/a/b'],
  '//127.0.0.1/a/b/c'      => ['http://127.1.1.2/a/b/c', 'http://127.1.1.2/a/b'],
  '//127.0.0.1/a/c'        => ['http://127.1.1.1/a/c', 'http://127.1.1.1/a'],
  '//127.0.0.1/b'          => ['http://127.1.1.0/b', 'http://127.1.1.0'],
  '//127.0.0.1:3000'       => ['http://127.1.1.3', 'http://127.1.1.3'],
  '//127.0.0.1:3000/a'     => ['http://127.1.1.4/a', 'http://127.1.1.4/a'],
  '//127.0.0.1:3000/a/b'   => ['http://127.1.1.5/a/b', 'http://127.1.1.5/a/b'],
  '//127.0.0.1:3000/a/b/c' => ['http://127.1.1.5/a/b/c', 'http://127.1.1.5/a/b'],
  '//127.0.0.1:3000/a/c'   => ['http://127.1.1.4/a/c', 'http://127.1.1.4/a'],
  '//127.0.0.1:3000/b'     => ['http://127.1.1.3/b', 'http://127.1.1.3'],
  '//127.0.0.1:4000'       => ['http://127.1.2.3:7123', 'http://127.1.2.3:7123'],
  '//127.0.0.1:4000/a'     => ['http://127.1.2.4:7124/a', 'http://127.1.2.4:7124/a'],
  '//127.0.0.1:4000/a/b'   => ['http://127.1.2.5:7125/a/b', 'http://127.1.2.5:7125/a/b'],
  '//127.0.0.1:4000/a/b/c' => ['http://127.1.2.5:7125/a/b/c', 'http://127.1.2.5:7125/a/b'],
  '//127.0.0.1:4000/a/c'   => ['http://127.1.2.4:7124/a/c', 'http://127.1.2.4:7124/a'],
  '//127.0.0.1:4000/b'     => ['http://127.1.2.3:7123/b', 'http://127.1.2.3:7123'],
  '//127.0.1.1/b'          => ["http+unix://$socket1/b", "http+unix://$socket1"],
  '//127.0.1.1/c'          => ["http+unix://$socket2/c", "http+unix://$socket2/c"],
  '//127.0.1.1/c/e'        => ["http+unix://$socket2/c/e", "http+unix://$socket2/c"],
  '//127.0.1.1/c/d'        => ["http+unix://$socket3/c/d", "http+unix://$socket3/c/d"],
  '//127.0.1.1/c/d/e'      => ["http+unix://$socket3/c/d/e", "http+unix://$socket3/c/d"],
  '//127.0.2.1'            => ["http+unix://$socket4", "http+unix://$socket4"],
  '//127.0.2.1/b'          => ["http+unix://$socket4/b", "http+unix://$socket4"],
  '//127.0.2.1/c'          => ["http+unix://$socket5/c", "http+unix://$socket5/c"],
  '//127.0.2.1/c/e'        => ["http+unix://$socket5/c/e", "http+unix://$socket5/c"],
  '//127.0.2.1/c/d'        => ["http+unix://$socket6/c/d", "http+unix://$socket6/c/d"],
  '//127.0.2.1/c/d/e'      => ["http+unix://$socket6/c/d/e", "http+unix://$socket6/c/d"],
);

for (sort keys %tests) {
  my $upstream = $t->app->proxy->upstream(Mojo::URL->new($_));
  ref $upstream eq 'Mojo::URL' or isa_ok $upstream, 'Mojo::URL' or next;
  ok $upstream eq $tests{$_}->[0] && $upstream->base eq $tests{$_}->[1],
    sprintf 'req %s upstream is %s and upstream base is %s', $_, $upstream, $upstream->base and next;
  is $upstream, $tests{$_}->[0];
  is $upstream->base, $tests{$_}->[1];
}

done_testing;
