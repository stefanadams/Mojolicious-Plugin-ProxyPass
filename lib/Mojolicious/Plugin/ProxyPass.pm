package Mojolicious::Plugin::ProxyPass;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

use Mojo::Collection;
use Mojo::File qw(path tempdir);
use Mojo::IOLoop;
use Mojo::Loader qw(load_class);
use Mojo::MemoryMap;
use Mojo::URL;
use Mojo::WebSocket qw(WS_PING);
use ProxyPass;
use ProxyPass::JWT;

use constant DEBUG => $ENV{PROXYPASS_DEBUG} //= 0;
use constant LOG_LEVEL => $ENV{PROXYPASS_LOG_LEVEL};

our $VERSION = '0.08';

has controller => 'ProxyPass';
has jwt => sub { ProxyPass::JWT->new };
has log_level => LOG_LEVEL;
has namespace => 'ProxyPass::Controller';
has uds_path => sub { $ENV{PROXYPASS_UDS_PATH} ? path($ENV{PROXYPASS_UDS_PATH})->make_path : undef };
has upstream => sub { {} };

sub register ($self, $app, $config) {

  # Initialize plugin
  $self->_initialize($app, $config);
  $app->plugin('HeaderCondition');
  $app->plugin('ProxyPass::Plugin::CaptureTX');
  $app->hook(before_server_start => sub { _before_server_start($self, @_) });
  $app->hook(before_dispatch => sub { _before_dispatch($self, @_) });
  $app->helper('proxy.error' => \&_error);
  $app->helper('proxy.jwt' => sub { state $jwt = $self->jwt });
  $app->helper('proxy.log' => sub { _log($self, @_) });
  $app->helper('proxy.login' => \&_login);
  $app->helper('proxy.pass' => sub { _catch_all($self, @_); $app });
  $app->helper('proxy.upstream' => sub { _upstream($self, @_) });
  $app->helper('reply.close' => \&_close);
  $app->helper('reply.ok' => \&_ok);
  $app->sessions->cookie_name('proxypass');
  $app->secrets($app->config->{proxypass}{secrets} || [__FILE__]);
  $app->max_request_size($app->config->{proxypass}{max_request_size} || 107374182);

  # Setup IdP routing
  my $idp = $app->routes->under('/idp')->to(namespace => $self->namespace, controller => $self->controller, cb => sub { 1 });
  $idp->post('/auth')->to('#idp_auth')->name('idp_auth');
  $idp->post('/verify')->to('#idp_verify')->name('idp_verify');

  # Setup ProxyPass routing
  my $r = $app->routes->add_condition(upstream => \&_requires_upstream);
  my $pp = $r->under('/proxypass')->to(namespace => $self->namespace, controller => $self->controller, cb => sub { 1 });
  $pp->get('/')->to('#proxypass', map => $self->{map})->name('proxypass');
  $pp->any('/login')->to('#login')->name('proxypass_login');
  $pp->any('/jwt')->to('#generate_token')->name('proxypass_jwt');
  $pp->any('/jwt/verify')->to('#verify_token')->name('proxypass_jwt_verify');
  $pp->any('/idp')->to('#idp')->name('proxypass_idp');
  $pp->any('/logout')->to('#logout')->name('proxypass_logout');

  return $self;
}

sub _before_dispatch ($self, $c) {
  my $id = $c->app->proxy->login;
  $c->session('ProxyPass' => $id || undef) if $id and not defined $c->session('ProxyPass');
  $c->proxy->log;
  return $c->proxy->error(400 => sprintf 'Host missing from HTTP request: %s', $c->tx->req->url->to_abs) unless $c->tx->req->headers->host;
}

sub _before_server_start ($self, $server, $app) {
  warn sprintf "Unix Domain Socket Path is %s\n", $self->uds_path if DEBUG && $self->uds_path;
}

sub _catch_all ($self, $c, $req_cb=undef, $res_cb=undef, $intercept=undef) {
  my $up = $c->app->routes->under->to(namespace => $self->namespace, controller => $self->controller, action => 'auth_upstream', config => $self->{config});
  $up->any('/*proxy_pass' => {proxy_pass => ''} => sub { $self->_proxy_pass(shift, $req_cb, $res_cb, $intercept) })
      ->requires('upstream');
}

sub _config ($self, $app_config, $plugin_config) {
  my $config = {%$app_config, %$plugin_config};
  $self->can($_) and $self->$_(/_path$/ && $config->{$_} ? path($config->{$_}) : $config->{$_}) for keys %$config;
  return $self->{config} = $config;
}

sub _cx ($tx) { ref $tx ? substr($tx->connection, 0, 7) : '-' }

sub _close ($c) {
  $c->rendered(503);
  Mojo::IOLoop->stream($c->tx->connection)->close;
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

sub _error ($c, $status, $message) {
  $c->proxy->log->trace($message) if DEBUG;
  $c->stash('proxy.error' => $message);
  return if $status == 100;
  if ($status =~ /^4/) {
    $c->reply->not_found;
    # $c->reply->close;
  }
  elsif ($status =~ /^5/) {
    $c->reply->exception($message);
  }
  else {
    $c->reply->exception($message);
  }
  return undef;
}

sub _initialize ($self, $app, $config) {
  $config = $self->_config($app->config->{proxy_pass} || {}, $config);
  my $controller_class = join '::', $self->namespace, $self->controller;
  load_class $controller_class and $app->warmup;
  push @{$app->renderer->classes}, $controller_class;
  $self->{connections} = {};

  # Initialize and refresh cache
  my $map = $self->{map} = Mojo::MemoryMap->new($config->{size});
  $map->writer->store({connections => {}});
  Mojo::IOLoop->recurring(5 => sub { $self->_memory_map });

  return $self;
}

sub _log ($self, $c, @contexts) {
  my $log = $c->stash('proxy_pass.log');
  if (!$log || @contexts) {
    unshift @contexts, $c->session('ProxyPass') || '?';
    unshift @contexts, $c->req->request_id;
    $log = $c->app->log->context(sprintf join(' ', map { '[%s]' } @contexts), @contexts);
    $log->level($self->log_level) if $self->log_level;
    $c->stash('proxy_pass.log' => $log);
  }
  return $log;
}

sub _login ($c) {
  my $jwt = $c->param('jwt') or return;
  my $id = $c->proxy->jwt->id($jwt) or return;
  my $admin = $c->proxy->jwt->admin($jwt);
  $c->session({ProxyPass => $id, ProxyPassAdmin => $admin});
  return $id;
}

sub _memory_map ($self) { $self->{map}->writer->change(sub { $_->{connections}{$$} = [map { {upstream => $_, session => $self->{connections}->{$_}->[0]} } keys $self->{connections}->%*] }) }

sub _ok { shift->render(data => '', status =>200) };

sub _proxy_pass ($self, $c, $req_cb=undef, $res_cb=undef, $intercept=undef) {
  $c->ua->cookie_jar->empty;
  $c->ua->inactivity_timeout(0);
  $c->inactivity_timeout(0);
  my $id = $c->session('ProxyPass') || _cx($c->tx);
  my $config = $self->{config};

  # gateway (gw) is the public-facing reverse proxy server
  my $gw_c           = $c;
  my $gw_tx          = $gw_c->tx;
  my $gw_ws          = $gw_tx if $gw_tx->is_websocket;
  my $gw_req         = $gw_tx->req;
  my $gw_req_headers = $gw_req->headers;
  my $gw_req_method  = $gw_req->method;
  my $gw_req_url     = $gw_req->url->to_abs;
  $gw_req_url->host or return $c->proxy->error(400 => 'Host missing from HTTP request');

  # Log gateway request
  _trace($c, 'GWProxyPassTX  >  %s', $gw_req_url->host_port);
  _debug(gw => $gw_tx->req);

  # origin (or) is the private intended-destination app server
  my $or_req_headers = $gw_req->headers->clone->dehop;
  my $or_req_method  = $gw_req_method;
  my $or_req_url     = $c->proxy->upstream;
  $or_req_url->host or return $c->proxy->error(400 => sprintf 'Upstream for %s not found', $gw_req_url->host_port);

  # Handle static files on behalf of the upstream
  my $key = join '', $c->tx->req->headers->host, $c->tx->req->url->path;
  if (($key) = grep { $key =~ $_ } keys $config->{static}->%*) {
    my $static_path = $config->{static}->{$key};
    my $key_path_parts  = Mojo::URL->new($key)->path->parts;
    my $real_path_parts = $c->tx->req->url->path->parts;
    shift @$real_path_parts for 1..$#$key_path_parts;
    my $static_file = path($static_path, @$real_path_parts);
    return -e $static_file ? $c->reply->file($static_file) : $c->reply->not_found;
  }

  # Build origin transaction
  my ($or_tx, $agent, $ping);
  if ($gw_tx->is_websocket) {
    $or_req_url->scheme($or_req_url->scheme =~ s/http/ws/r);
    _trace($c, 'GWProxyPassTX ... (%s)', _cx($gw_tx));
    $or_tx = $c->ua->build_websocket_tx($or_req_url => $or_req_headers->to_hash);
    # For some reason, the gateway websocket connection keeps timing out at 100s
    $ping = Mojo::IOLoop->recurring(60 => sub {
      $gw_tx->send([1, 0, 0, 0, WS_PING, '1']);
      _trace($c, 'GWProxyPassTX WSP (%s)', _cx($gw_tx));
    });
    $agent = 'ua';
  }
  else {
    $or_tx = $c->ua->build_tx($or_req_method => $or_req_url => $or_req_headers->to_hash);
    $agent = 'proxy';
  }

  # Modify origin request
  $or_tx->req->content($gw_req->content);
  $or_tx->req->headers->header('X-Forwarded-For'   => $gw_tx->remote_address);
  $or_tx->req->headers->header('X-Forwarded-Host'  => $gw_req_url->host_port);
  $or_tx->req->headers->header('X-Forwarded-Proto' => $gw_req_url->scheme);
  $or_tx->req->headers->header('X-ProxyPass'       => "Request/$id");
  $or_tx->req->headers->header('X-ProxyPass-ID'    => $c->session('ProxyPass')) if $c->session('ProxyPass');
  $or_tx->req->headers->header('X-ProxyPass-Admin' => $c->session('ProxyPassAdmin')) if $c->session('ProxyPassAdmin');
  $or_tx->req->headers->header('X-Request-Base'    => $or_req_url->base);
  $or_tx->req->headers->header('Upgrade'           => $gw_req->headers->upgrade) if $gw_req->headers->upgrade;
  $or_tx->req->headers->header('Connection'        => $gw_req->headers->connection) if $gw_req->headers->connection;

  # Customize origin request
  $req_cb->($c, $or_tx) if ref $req_cb eq 'CODE';

  # Log origin request
  _trace($c, 'GWProxyPassTX >>> %s', join '', path($or_req_url->host)->basename, $or_req_url->path);
  _debug(or => $or_tx->req);

  # Intercept filtered responses for inspection/modification
  return if ($intercept || Mojo::Collection->new)->grep(sub { $_->[0]->($c, $or_tx) })->first(sub {
    my $intercept_cb = $_->[1];
    $c->ua->start_p($or_tx)->then(sub ($tx) {
      $c->log->info(sprintf 'Filtering %s', $or_tx->req->url);
      $c->res->headers->from_hash($tx->res->headers->to_hash);
      $intercept_cb->($c, $tx);
    })->catch(sub ($err) {
      $c->proxy->error(400 => $c->app->mode eq 'development' ? $err : 'Could not connect to backend web service!');
    });
  });

  # Handle downstream websocket messages
  $gw_c->on(message => sub ($c, $msg) {
    my $or_ws = $self->{connections}->{$or_tx->connection}->[1];
    return unless $or_ws->is_websocket;
    _trace($c, 'GWProxyPassWS  >  (%s)', _cx($gw_ws));
    _trace($c, 'GWProxyPassWS >>> (%s)', _cx($or_ws));
    $or_ws->send($msg);
  });
  $gw_c->on(finish => sub ($c, $code=undef, $reason=undef) {
    return unless $c->tx->is_websocket;
    Mojo::IOLoop->remove($ping) if $ping;
    _trace($c, 'GWProxyPassWS <x> (%d|%s)', $code, join ' ', grep {$_} _cx($gw_ws), $reason);
    delete $self->{connections}->{$or_tx->connection};
  });

  # Start non-blocking request
  $c->$agent->start_p($or_tx)->then(sub ($tx=undef) {
    return unless $tx && $tx->is_websocket;

    # Start new websocket connection
    my $or_ws = $tx;
    $self->{connections}->{$tx->connection} = [$id, $or_ws];
    _trace($c, 'ORProxyPassWS <=> (%s)', _cx($or_ws));
    my $stream = Mojo::IOLoop->stream($or_ws->connection // '');
    $stream->timeout(0) if $stream;

    # Handle upstream websocket messages
    $or_ws->on(message => sub ($ws, $msg) {
      _trace($c, 'ORProxyPassWS <<< (%s)', _cx($or_ws));
      _trace($c, 'ORProxyPassWS  <  (%s)', _cx($gw_ws));
      $gw_ws->send($msg);
    });
    $or_ws->on(finish => sub ($ws, $code, $reason) {
      _trace($c, 'ORProxyPassWS <X> (%d|%s)', $code, join ' ', grep {$_} _cx($or_ws), $reason);
      $gw_ws->finish;
    });
  })->catch(sub ($err) {
    _trace($c, 'GWProxyPassTX <=X %s(%s)', $gw_req_url->host_port, $err);
    my $error = sprintf 'Proxy error connecting to backend %s from %s: %s', $or_req_url->host_port, $gw_req_url->host_port, $err;
    $c->proxy->error(400 => $c->app->mode eq 'development' ? $error : 'Could not connect to backend web service!');
  });

  # Modify origin response
  $or_tx->res->content->once(body => sub ($or_content) {
    # Log origin response
    _trace($c, 'ORProxyPassTX <<< %s/%s', _res_code_length($or_tx));
    _debug(or => $or_tx->res);

    # Add some helper headers
    $c->res->headers->server("ProxyPass/$VERSION");
    $c->res->headers->header('X-ProxyPass' => "Response/$id");

    # Customize gateway response
    $res_cb->($c, $or_tx) if ref $res_cb eq 'CODE';

    # Log redirect
    if (my $or_res_location = $or_tx->res->headers->location) {
      $or_res_location = Mojo::URL->new($or_res_location);
      _trace($c, 'ORProxyPassTX <<< (%s)', $or_res_location->host_port);
      _trace($c, 'ORProxyPassTX  <  (%s)', $gw_tx->res->headers->location);
    }

    # Log gateway response
    _trace($c, 'ORProxyPassTX %s=> %s/%s', _resume($c, $gw_tx, $or_tx), _res_code_length($gw_tx));
    _debug(gw => $gw_tx->res);
  });

  return $or_tx;
}

sub _res_code_length ($tx) { ($tx->res->code, $tx->res->headers->content_length//'') }

# Ensure transaction resumes when conditions prevent resuming
sub _resume ($c, $gw_tx, $or_tx) {
  return '<' unless (!$gw_tx->res->headers->content_length && !$gw_tx->res->is_empty)
  || $gw_tx->req->method eq 'HEAD';
  $or_tx->res->once(finish => sub { $gw_tx->resume });
  return 'X';
}

sub _requires_upstream ($route, $c, $captures, $undef) {
  return 1 if $c->proxy->upstream;
  $c->proxy->error(100 => sprintf 'skip ProxyPass: configuration for upstream %s not found (HTTP/%s)', $c->tx->req->headers->host, $c->tx->req->version);
  return undef;
}

sub _trace {
  my ($c, $msg) = (shift, shift);
  @_ = grep { defined } @_;
  return unless @_;
  my ($name) = ($msg =~ /^(\w+)/);
  if (my $username = $c->stash($name)) {
    $c->proxy->log->trace(sprintf "[%s] $msg", $username, @_);
  }
  else {
    $c->proxy->log->trace(sprintf $msg, @_);
  }
};

sub _upstream ($self, $c, $url=undef) {
  $url ||= $c->tx->req->url;
  my $upstream = $c->stash("proxy.upstream.$url");
  return $upstream if $upstream;
  my $proxypass = ProxyPass->new(uds_path => $self->uds_path, config => $self->upstream)->find($url)->first or return;
  $upstream = $proxypass->proxypass($url);
  $c->proxy->log->trace(sprintf 'configuration for upstream %s found: %s', $url, $upstream) if DEBUG;
  $c->stash("proxy.upstream.$url" => $upstream);
  return $upstream;
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
    auth_upstream => ['127.0.0.1:3000'],
    static => {
      '127.0.0.1/path' => '/static/path',
    },
    uds_path => tempdir,
    upstream => {
      '127.0.0.1' => '127.0.0.1:3000'
    },
  };

=head1 DESCRIPTION

L<Mojolicious::Plugin::ProxyPass> is a L<Mojolicious> plugin to provide reverse proxy functionality for any HTTP
traffic, including support for websockets.  Extensible authentication allows configured upstreams to first require
authentication.

=head1 ATTRIBUTES

L<Mojolicious::Plugin::ProxyPass> implements the following attributes.

=head2 controller

  my $secret = $proxy_pass->controller;
  $c         = $proxy_pass->controller($name);

Name of controller relative to L</"namespace"> for internal /proxypass routes, defaults to ProxyPass.

=head2 jwt

  my $secret = $proxy_pass->jwt;
  $c         = $proxy_pass->jwt($jwt);

JWT object to optionally use for ProxyPass authentciation, defaults to a new L<ProxyPass::JWT> instance.

=head2 namespace

  my $secret = $proxy_pass->namespace;
  $c         = $proxy_pass->namespace($namespace);

Namespace for internal /proxypass routes controller, defaults to ProxyPass::Controller.

=head2 uds_path

  my $path = $proxy_pass->uds_path;
  $c       = $proxy_pass->uds_path($path);

Set the L<Mojo::File/"path"> to where unix domain sockets are stored, defaults to the value of the environment
variable PROXYPASS_UDS_PATH or undef.

=head2 upstream

  my $hash = $proxy_pass->upstream;
  $c       = $proxy_pass->upstream($hash);

A hash mapping upstream servers for each handled request L<Mojo::URL/"host_port">.

=head1 HELPERS

L<Mojolicious::Plugin::ProxyPass> implements the following helpers.

=head2 proxy->error

  # undef
  $app->proxy->error($code => $message);

Render not_found if $code is 4xx or $message exception if $code is 5xx. Always returns undef.

=head2 proxy->jwt

  $jwt = $app->proxy->jwt;

Access the plugin jwt instance.

=head2 proxy->log

  $log = $app->proxy->log(@contexts);

The ProxyPass L<Mojo::Log> instance based on the application log. This is very useful for controlling log levels
for ProxyPass separately from the application log.

If contexts are provided, these are applied to the L<Mojo::Log> instance. The request_id and ProxyPass authenticated
ID are always added.

  $log = $app->proxy->log(@contexts);

=head2 proxy->login

  $id = $app->proxy->login;

Meant to be redefined by the application.  Should implement authentication mechanism and verify the submitted values.
Must set the ProxyPass session value to the login ID. Should set the ProxyPassAdmin session value. Returns the login ID
if successful, otherwise undef.

=head2 proxy->pass

  $origin_tx = $app->proxy->pass;
  $origin_tx = $app->proxy->pass($req_cb, $res_cb, $intercept_collection);

A catch all route for any request method, including websockets. Proxy the connection to the configured L<"upstream">
server and return the response to the client. If a unix domain socket in the L<"uds_path"> exists, use it instead of
the specified L<"upstream"> server.

proxy->pass creates a catch-call route for requests that require a configured upstream and are first handled by the
L</"namespace">::L</"controller"> class L</"auth_upstream"> action.

The default L<ProxyPass::Controller::ProxyPass> controller checks that authentication is required for the upstream
and if not authenticated, is redirected to a login page.

Additionally:

  - If the upstream server is configured to require it, the gateway request will call the L<"login"> helper unless the
    request is already signed
  - If the upstream server cannot be determined, ProxyPass is aborted with "Service not available"
  - A signed cookie is added to the gateway response if the upstream server is configured to require it
  - If needed, the gateway transaction is resumed after the origin transaction is finished
  - Establishes and retains websocket connections if requested by the client

Optional arguments:

=over 4

=item req_cb

  $app->proxy->pass(sub ($c, $or_tx) { $or_tx->req->headers->user_agent('MojoProxy/1.0') });

A callback to modify the origin request before it is sent.

=item res_cb

  $app->proxy->pass(undef, sub ($c, $or_tx) { $or_tx->res->headers->header('X-ProxyPass' => 'Response') });

A callback to modify the gateway response before it is sent.

=item intercept_collection

  $app->proxy->pass(undef, undef, Mojo::Collection->new(
    [
      sub ($c, $or_tx) { $or_tx->res->headers->header('X-ProxyPass' => 'Intercept') },
      sub ($c, $up_tx) { $up_tx->res->headers->header('X-ProxyPass' => 'Intercept') },
    ]
  ));

A collection of callbacks to filter or intercept the origin response before it is sent to the gateway response.

=back

=head2 proxy->upstream

  $host_port = $c->proxy->upstream;

Get the L<"upstream"> server for this transaction.

=head1 ROUTES

=head2 proxypass (GET /proxypass)

Route to status action of L</"controller_class">. Stashes the L<Mojo::MemoryMap> object in map.

Defaults to render a JSON response of all current connection IDs.

=head2 proxypass_login (ANY /proxypass/jwt)

Route to generate_token action of L</"controller_class">, available to ProxyPassAdmin sessions to generate additional
JWTs.

Defaults to rendering the generate_token template if authenticated as ProxyPassAdmin.

=head2 proxypass_login (ANY /proxypass/login)

Route to login action of L</"controller_class">, sets the ProxyPass session value to the login ID.

Defaults to rendering the logged_in template if authenticated, login_form otherwise.

=head2 proxypass_logout (ANY /proxypass/logout)

Route to logout action of L</"controller_class">, expires the session.

Defaults to rendering the logged_out template.

=head1 METHODS

L<Mojolicious::Plugin::ProxyPass> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 DEBUGGING

=head2 PROXYPASS_DEBUG

Set to a true value to enable gateway and origin request and response logging, defaults to false.

=head2 PROXYPASS_LOG_LEVEL

Set the log level for ProxyPass logging, defaults to trace.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<https://mojolicious.org>.

=cut
