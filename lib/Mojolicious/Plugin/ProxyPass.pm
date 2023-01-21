package Mojolicious::Plugin::ProxyPass;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

use Mojo::File qw(path tempdir);
use Mojo::URL;
use ProxyPass;
use ProxyPass::JWT;

use constant DEBUG => $ENV{MOJO_PROXY_DEBUG} //= 0;

our $VERSION = '0.02';

has default_url => 'http://example.com';
has jwt => sub { ProxyPass::JWT->new };
has uds_path => sub { $ENV{MOJO_PROXY_UDS_PATH} ? path($ENV{MOJO_PROXY_UDS_PATH})->make_path : tempdir };
has upstream => sub { {} };

sub register {
  my ($self, $app, $config) = @_;

  $config = $app->config('proxy_pass') || {} unless keys %$config;
  $self->can($_) and $self->$_(/_path$/ && $config->{$_} ? path($config->{$_}) : $config->{$_}) for keys %$config;
  push @{$app->renderer->classes}, __PACKAGE__, 'ProxyPass::Controller::ProxyPass';

  $app->plugin('HeaderCondition');
  $app->hook(before_server_start => sub ($server, $app) {
    warn sprintf "Unix Domain Socket Path is %s\n", $self->uds_path if $self->uds_path;
  });

  $app->helper('proxy.auth' => sub ($c, $upstream, $auth_upstream) {
    if (my $id = $c->session('ProxyPass')) {
      push @{$c->log->{context}}, "[$id]";
      return 1;
    }
    $c->redirect_to($c->url_for('proxy_pass_login')->query(_URL => $c->req->url->to_abs->to_string));
    return undef;
  });

  $app->helper('proxy.default_url' => sub ($c) { $self->default_url });

  $app->helper('proxy.error' => sub ($c, $status, $message) {
    $c->log->error($message);
    $c->render(status => $status, text => $message);
    return undef;
  });

  $app->helper('proxy.jwt' => sub ($c) { state $jwt = $self->jwt });

  $app->helper('proxy.login' => sub { 1 });

  $app->helper('proxy.logout' => sub { 1 });

  $app->helper('proxy.pass' => sub ($c, $req_cb=undef, $res_cb=undef) {
    my $r = $app->routes;
    $r->add_condition(proxy_pass => sub ($route, $c, $captures, $undef) {
      return 1 if $c->proxy->upstream;
      my $error = sprintf 'Configuration for upstream %s not found', $c->tx->req->headers->host;
      $c->log->trace($error);
      $c->stash(upstream_error => $error);
      return undef;
    });
    my $pp = $r->under('/proxypass');
    $pp->any('/login')->to('proxy_pass#login', namespace => 'ProxyPass::Controller')->name('proxy_pass_login');
    $pp->any('/logout')->to('proxy_pass#logout', namespace => 'ProxyPass::Controller')->name('proxy_pass_logout');
    my $up = $r->under(sub ($c) {
      $c->tx->req->headers->host or return $c->proxy->error(400 => 'Host missing from HTTP request');
      my $upstream = $c->proxy->upstream or return $c->proxy->error(400 => sprintf 'Configuration for upstream %s not found', $c->tx->req->headers->host);
      my $auth_upstream = $config->{auth_upstream} || [];
      return 1 unless grep { $_ eq $upstream->host_port } @$auth_upstream;
      $c->proxy->auth($upstream, $auth_upstream);
    });
    $up->any('/*proxy_pass' => {proxy_pass => ''} => sub { $self->_proxy_pass(shift, $req_cb, $res_cb) })
       ->requires('proxy_pass');
    return $app;
  });

  $app->helper('proxy.upstream' => sub ($c, $url=undef) { $self->_upstream($url||$c->tx->req->url) });

  return $self;
}

sub _debug ($label, $msg) {
  return unless DEBUG;
  my ($msg_type) = ((ref $msg) =~ /^Mojo::Message::(\w+)$/);
  if ($label =~ /^g/i) {
    if ($msg->can('url')) {
      warn sprintf "Gateway $msg_type Abs URL: %s\n", $msg->url->to_abs;
      warn sprintf "Gateway $msg_type Base URL: %s\n", $msg->url->base;
    }
    warn sprintf "Gateway $msg_type:\n%s", $msg->headers->to_string;
  }
  elsif ($label =~ /^o/i) {
    if ($msg->can('url')) {
      warn sprintf "Origin $msg_type Abs URL: %s\n", $msg->url->to_abs;
      warn sprintf "Origin $msg_type Base URL: %s\n", $msg->url->base;
      warn sprintf "Origin $msg_type:\n%s", $msg->to_string;
    }
    else {
      warn sprintf "Origin $msg_type:\n%s\n", $msg->headers->to_string;
    }
  }
}

sub _proxy_pass ($self, $c, $req_cb=undef, $res_cb=undef) {
  $c->ua->cookie_jar->empty;
  # gateway (gw) is the public-facing reverse proxy server
  my $gw_c           = $c;
  my $gw_tx          = $gw_c->tx;
  my $gw_req         = $gw_tx->req;
  my $gw_req_headers = $gw_req->headers;
  my $gw_req_method  = $gw_req->method;
  my $gw_req_url     = $gw_req->url->to_abs;
  $gw_req_url->host or return $c->proxy->error(400 => 'Host missing from HTTP request');

  # Log gateway request
  _trace($c, 'ProxyPass  >  %s', $gw_req_url->host_port);
  _debug(gw => $gw_tx->req);

  # origin (or) is the private intended-destination app server
  my $or_req_headers = $gw_req->headers->clone->dehop;
  my $or_req_method  = $gw_req_method;
  my $or_req_url     = $c->proxy->upstream;
  $or_req_url->host or return $c->proxy->error(400 => sprintf 'Upstream for %s not found', $gw_req_url->host_port);

  # Build origin transaction
  my $or_tx = $c->ua->build_tx($or_req_method => $or_req_url => $or_req_headers->to_hash);

  # Modify origin request
  $or_tx->req->content($gw_req->content);
  $or_tx->req->headers->header('X-Forwarded-For'   => $gw_tx->remote_address);
  $or_tx->req->headers->header('X-Forwarded-Host'  => $gw_req_url->host_port);
  $or_tx->req->headers->header('X-Forwarded-Proto' => $gw_req_url->scheme);
  $or_tx->req->headers->header('X-ProxyPass'       => 'Request');
  $or_tx->req->headers->header('X-Request-Base'    => $or_req_url->base);
  $or_tx->req->headers->header('Upgrade'           => $gw_req->headers->upgrade) if $gw_req->headers->upgrade;
  $or_tx->req->headers->header('Connection'        => $gw_req->headers->connection) if $gw_req->headers->connection;

  # Customize origin request
  $req_cb->($c, $or_tx) if ref $req_cb eq 'CODE';

  # Log origin request
  _trace($c, 'ProxyPass >>> %s', $or_req_url);
  _debug(or => $or_tx->req);

  # Start non-blocking request
  $c->proxy->start_p($or_tx)->catch(sub ($err) {
    my $error = sprintf 'Proxy error connecting to backend %s from %s: %s', $or_req_url->host_port, $gw_req_url->host_port, $err;
    $c->log->error($error);
    $c->proxy->error(400 => $self->app->mode eq 'development' ? $error : 'Could not connect to backend web service!');
  });

  # Modify origin response
  $or_tx->res->content->once(body => sub ($or_content) {
    # Log origin response
    _trace($c, 'ProxyPass <<< %s/%s', _res_code_length($or_tx));
    _debug(or => $or_tx->res);

    # Add some helper headers
    $c->res->headers->server("ProxyPass/$VERSION");
    $c->res->headers->header('X-ProxyPass' => 'Response');

    # Customize gateway response
    $res_cb->($c, $or_tx) if ref $res_cb eq 'CODE';

    # Log redirect
    if (my $or_res_location = $or_tx->res->headers->location) {
      $or_res_location = Mojo::URL->new($or_res_location);
      _trace($c, 'ProxyPass <<< (%s)', $or_res_location->host_port);
      _trace($c, 'ProxyPass  <  (%s)', $gw_tx->res->headers->location);
    }

    # Log gateway response
    _trace($c, 'ProxyPass %s<  %s/%s', _resume($c, $gw_tx, $or_tx), _res_code_length($gw_tx));
    _debug(gw => $gw_tx->res);
  });

  return $or_tx;
}

sub _res_code_length ($tx) { ($tx->res->code, $tx->res->headers->content_length//'') }

# Ensure transaction resumes when conditions prevent resuming
sub _resume ($c, $gw_tx, $or_tx) {
  return ' ' unless (!$gw_tx->res->headers->content_length && !$gw_tx->res->is_empty)
  || $gw_tx->req->method eq 'HEAD';
  $or_tx->res->once(finish => sub { $gw_tx->resume });
  return 'X';
}

sub _trace {
  my ($c, $msg) = (shift, shift);
  return unless @_;
  my ($name) = ($msg =~ /^(\w+)/);
  if (my $username = $c->stash($name)) {
    $c->log->trace(sprintf "[%s] $msg", $username, @_);
  }
  else {
    $c->log->trace(sprintf $msg, @_);
  }
};

sub _upstream ($self, $url) {
  my $proxypass = ProxyPass->new(uds_path => $self->uds_path, config => $self->upstream)->find($url)->first or return;
  $proxypass->proxypass($url);
}

1;

=encoding utf8

=head1 NAME

Mojolicious::Plugin::ProxyPass - Mojolicious Plugin to provide provide reverse proxy functionality

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('ProxyPass');

  # Mojolicious::Lite
  plugin 'ProxyPass' => {
    uds_path => tempdir,
    upstream => {
      '127.0.0.1' => '127.0.0.1:3000'
    },
  };

=head1 DESCRIPTION

L<Mojolicious::Plugin::ProxyPass> is a L<Mojolicious> plugin to provide reverse proxy functionality.

=head1 ATTRIBUTES

L<Mojolicious::Plugin::ProxyPass> implements the following attributes.

=head2 jwt_secret

  my $secret = $proxy_pass->jwt_secret;
  $c         = $proxy_pass->jwt_secret($secret);

Set the JWT secret, defaults to __FILE__.

=head2 jwt_timeout

  my $seconds = $proxy_pass->jwt_timeout;
  $c          = $proxy_pass->jwt_timeout($second);

Set the JWT timeout value in seconds, defaults to 600 (10 minutes).

=head2 jwt_upstream

  my $upstream = $proxy_pass->jwt_upstream;
  $c           = $proxy_pass->jwt_upstream([@upstream]);

Set the upstream hosts that require signed transactions, defaults to an empty list.

Undefine to completely disable JWT support.

=head2 uds_path

  my $path = $proxy_pass->uds_path;
  $c       = $proxy_pass->uds_path($path);

Set the L<Mojo::File/"path"> to where unix domain sockets are stored.

=head2 upstream

  my $hash = $proxy_pass->upstream;
  $c       = $proxy_pass->upstream($hash);

A hash mapping upstream servers for each handled request L<Mojo::URL/"host_port">.

=head1 HELPERS

L<Mojolicious::Plugin::ProxyPass> implements the following helpers.

=head2 proxy->jwt_url

  $url_str = $app->proxy->jwt_url;

A URL with a JWT token that can be used to sign all subsequent transactions.

=head2 proxy->login

  $c->proxy->login;

Handle unsigned requests that require it. Meant to be redefined after this plugin is loaded.

=head2 proxy->pass

  $origin_tx = $app->proxy->pass;

Proxy the connection to the L<"upstream"> server and return the response to the client. If a unix domain socket in the
L<"uds_path"> exists, use it instead of the specified L<"upstream"> server.

This helper is mostly just logging, but does provide some important benefits:

  - If the upstream server is configured to require it, the gateway request will call the L<"login"> helper unless the
    request is already signed
  - If the upstream server cannot be determined, ProxyPass is aborted with "Service not available"
  - A signed cookie is added to the gateway response if the upstream server is configured to require it
  - If needed, the gateway transaction is resumed after the origin transaction is finished

=head2 proxy->sign

  $c->proxy->sign($cookie_name, $identifier);
  $c->proxy->sign($cookie_name);

Sets the identifier for the signed cookie and then stores the session.

=head2 proxy->upstream

  $host_port = $c->proxy->upstream;

Get the L<"upstream"> server for this transaction.

=head1 METHODS

L<Mojolicious::Plugin::ProxyPass> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 DEBUGGING

=head2 MOJO_PROXY_DEBUG

Set to a true value to enable gateway and origin request and response logging.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<https://mojolicious.org>.

=cut
