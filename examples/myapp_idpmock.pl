#!/usr/bin/env perl
use Mojolicious::Lite -signatures, -async_await;

use Mojo::JSON qw(encode_json decode_json);
use Mojo::Util qw(b64_decode b64_encode);
use ProxyPass::JWT;

plugin 'Config' => {default => {idp => '/idp/'}};

hook 'after_dispatch' => sub ($c) {
  $c->res->headers->header('X-Set-Cookie-Session' => encode_json($c->session)) if keys $c->session->%*;
  $c->log->info(sprintf '[%d] [%s] %s (%s log)', $c->res->code, $c->username, $c->req->url->path, $c->stash('mock') // 'Application');
};

helper 'claims' => sub ($c, $val) {
  ref $val eq 'HASH'
    ? b64_encode(encode_json($val), '')
    : Mojo::JSON::Pointer->new(decode_json(b64_decode($val) || '{}'))
};
helper 'jwt' => sub { state $jwt = ProxyPass::JWT->new(secret => shift->app->secrets->[0]) };
helper 'reply.ok' => sub { shift->render(data => '', status => 204) };
helper 'reply.idp' => sub ($c) { $c->render(text => $c->jwt->token($c->stash('ProxyPass'))) };
helper 'reply.jwt' => sub ($c, $claims) { $c->render(text => $c->jwt->token($c->claims($claims))) };
helper 'reply.unauthorized' => sub ($c) {
  $c->render(template => 'unauthorized', status => 401);
};
helper 'username' => sub ($c) {
  my $username = $c->param('username');
  $c->session('ProxyPass') || $c->stash('ProxyPass') || ($username ? "!$username" : 'anonymous');
};

helper 'idp.url' => sub ($c, $path) { Mojo::URL->new($c->config('idp'))->clone->path($path) };
helper 'idp.auth_p' => sub ($c, $proxy_pass, $url) {
  $c->ua->post_p($c->idp->url('auth/')->path($c->param('force')//'') => $c->claims({url => $url, ProxyPass => $proxy_pass}))->then(sub ($tx) {
    die 'Unauthorized: invalid ProxyPass' unless $tx->result->is_success;
  });
};
helper 'idp.verify_p' => sub ($c) {
  return Mojo::Promise->new->resolve if $c->session('ProxyPass');
  return Mojo::Promise->new->reject('missing idp') unless my $idp = $c->param('idp') || $c->cookie('idp');
  $c->ua->post_p($c->idp->url('verify/')->path($c->param('force')//'') => $idp)->then(sub ($tx) {
    die 'Unauthorized: invalid idp jwt' unless $tx->result->is_success;
    $c->session($c->jwt->decode($idp)); # The application session cookie; unique to the application (can this session cookie be shared across multiple apps?)
    $c->cookie(idp => $idp); # The identity provider session cookie; unique to the application (can this session cookie be shared across multiple apps? can it be renewed?)
  });
};

# Application Protected routes
group {
  under '/protected' => sub ($c) {
    $c->idp->verify_p->then(sub {
      $c->continue;
    })->catch(sub ($err) {
      $c->flash(url => $c->req->url->to_abs->to_string)->reply->unauthorized;
    });
    return undef;
  };

  get '/index' => sub ($c) {
    $c->render(template => 'index');
  };
};

# Application Public routes
group {
  get '/' => sub ($c) {
    $c->render(template => 'index');
  };

  any '/login/:username' => {username => ''} => sub ($c) {
    $c->render_later;
    $c->idp->auth_p($c->param('username'), $c->param('url') || $c->flash('url'))->then(sub {
      $c->reply->unauthorized;
    })->catch(sub ($err) {
      $c->reply->exception($err);
    });
  } => 'login';
};

# Mock the remote Identity Provider
group {
  under '/idp' => {mock => 'Identity Provider'};

  post '/auth/:force' => {force => 1} => sub ($c) {
    $c->stash($c->claims($c->req->body)->data);
    return $c->reply->exception(sprintf 'Cannot find ID: %s', $c->stash('ProxyPass')) unless $c->param('force') && $c->stash('ProxyPass');
    $c->log->trace(sprintf 'IdP authentication for %s', $c->stash('ProxyPass'));
    $c->log->debug(sprintf 'User to click: %s', Mojo::URL->new($c->stash('url'))->query(idp => $c->jwt->token($c->stash('ProxyPass'))));
    $c->reply->ok;
  } => 'idp_auth';

  post '/verify/:force' => {force => 1} => sub ($c) {
    $c->stash($c->jwt->decode($c->req->body));
    return $c->reply->exception(sprintf 'Cannot find ProxyPass: %s', $c->stash('ProxyPass')) unless $c->param('force') && $c->stash('ProxyPass');
    $c->log->trace(sprintf 'IdP verified for %s', $c->stash('ProxyPass'));
    $c->reply->idp;
  } => 'idp_verify';
};

app->start;

=encoding utf8

=head1 NAME

myapp.pl - Example app to demonstrate the ProxyPass IdP integration

=head1 SYNOPSIS


  # User -> Protected Application = Unauthorized, nothing to think about
  $ perl examples/myapp.pl get /protected/index title text
  [2025-10-05 20:55:59.92786] [3924671] [info] [Pqu0H6D22fpQ] [401] [anonymous] /protected/index (Application log)
  Unauthorized

  # User -> Protected Application with Expired Token = Unauthorized, according to IdP
  $ perl examples/myapp.pl get '/protected/index?idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE1MTEwfQ.BHFi4yXkGywMQjxySzA4VDKaubEIEKE6eqE3NCAeoOo' title text
  [2025-10-05 20:56:15.97639] [3924730] [error] [TGks8Dvyy1wk] JWT has expired at lib/ProxyPass/JWT.pm line 12.
  [2025-10-05 20:56:15.99879] [3924730] [info] [TGks8Dvyy1wk] [500] [anonymous] /idp/verify (Identity Provider log)
  [2025-10-05 20:56:16.00760] [3924730] [info] [im0syEIbThE3] [401] [anonymous] /protected/index (Application log)
  Unauthorized

  # User with Token -> Requesting Protected Application = So far so good, Redirect to IdP to authenticate user
  $ perl examples/myapp.pl get -M POST -f url=/protected/index /login/abc123 title text
  [2025-10-05 21:00:32.37234] [3925562] [debug] [DObnZdoTqh8K] /protected/index?idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyfQ.Jdov1pRLEdVKzolPsNALAg2-QaICgOzTyB-TWnM_vdk
  [2025-10-05 21:00:32.37325] [3925562] [info] [DObnZdoTqh8K] [204] [abc123] /idp/auth (Identity Provider log)
  [2025-10-05 21:00:32.38032] [3925562] [info] [lf5-GLDAVlsV] [401] [!abc123] /login/abc123 (Application log)
  Unauthorized

  # User with verified Token -> Protected Application = Welcome, token verified by IdP = Application sets Cookie to avoid constant IdP verification
  $ perl examples/myapp.pl get '/protected/index?idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyfQ.Jdov1pRLEdVKzolPsNALAg2-QaICgOzTyB-TWnM_vdk' title text
  [2025-10-05 21:01:14.98506] [3925693] [info] [QLNgKUF-vW0x] [200] [abc123] /idp/verify (Identity Provider log)
  [2025-10-05 21:01:14.99038] [3925693] [info] [f67dl_iffYOj] [200] [abc123] /protected/index (Application log)
  Welcome

  # User with valid Cookie -> Protected Application = Welcome, token verified by Application Cookie
  $ perl examples/myapp.pl get -H "Cookie: mojolicious=eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyLCJleHBpcmVzIjoxNzU5NzE5NzEzfQ----2f97d74021c7b45e3e2cba668d595a8077e3599f769e8ca60df6f2cbf8063a0c" /protected/index title text
  [2025-10-05 21:02:22.38143] [3925897] [info] [D8U5VhdDstrv] [200] [abc123] /protected/index (Application log)
  Welcome

  # User with valid Cookie -> Protected Application = Welcome, token verified by IdP from IdP Cookie
  $ perl examples/myapp.pl get -H "Cookie: idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyfQ.Jdov1pRLEdVKzolPsNALAg2-QaICgOzTyB-TWnM_vdk" /protected/index title text
  [2025-10-05 21:02:51.04332] [3926012] [info] [hTh8r9DPH580] [200] [abc123] /idp/verify (Identity Provider log)
  [2025-10-05 21:02:51.04821] [3926012] [info] [JRwsRdF_kuYr] [200] [abc123] /protected/index (Application log)
  Welcome

  # User with Token -> Requesting Protected Application = So far so good, Redirect to IdP to authenticate user (but for testing, force=0 to not authenticate)
  $ perl examples/myapp.pl get '/protected/index?idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyfQ.Jdov1pRLEdVKzolPsNALAg2-QaICgOzTyB-TWnM_vdk&force=0' title text
  [2025-10-05 21:03:39.39294] [3926197] [error] [mWqsbLNULXYH] Cannot find ProxyPass: abc123
  [2025-10-05 21:03:39.41519] [3926197] [info] [mWqsbLNULXYH] [500] [abc123] /idp/verify/0 (Identity Provider log)
  [2025-10-05 21:03:39.42228] [3926197] [info] [JS4lsJrmtcKi] [401] [anonymous] /protected/index (Application log)
  Unauthorized

  # User with IdP Cookie -> Protected Application = So far so good, Redirect to IdP to authenticate user (but for testing, force=0 to not authenticate)
  $ perl examples/myapp.pl get -H "Cookie: idp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyfQ.Jdov1pRLEdVKzolPsNALAg2-QaICgOzTyB-TWnM_vdk" /protected/index?force=0 title text
  [2025-10-05 21:04:24.12560] [3926355] [error] [MfOY7sh2PeJs] Cannot find ProxyPass: abc123
  [2025-10-05 21:04:24.14943] [3926355] [info] [MfOY7sh2PeJs] [500] [abc123] /idp/verify/0 (Identity Provider log)
  [2025-10-05 21:04:24.15751] [3926355] [info] [Md93KeYCtQda] [401] [anonymous] /protected/index (Application log)
  Unauthorized

  # User with Application Cookie -> Protected Application = Welcome, token verified by Application Cookie (force=0 is only for testing IdP, no effect here)
  $ perl examples/myapp.pl get -H "Cookie: mojolicious=eyJQcm94eVBhc3MiOiJhYmMxMjMiLCJQcm94eVBhc3NBZG1pbiI6MCwiZXhwIjoxNzU5NzE2NjMyLCJleHBpcmVzIjoxNzU5NzE5NzEzfQ----2f97d74021c7b45e3e2cba668d595a8077e3599f769e8ca60df6f2cbf8063a0c" /protected/index?force=0 title text
  [2025-10-05 21:04:59.71314] [3926500] [info] [but-YBW7c7Hb] [200] [abc123] /protected/index (Application log)
  Welcome

=cut

__DATA__

@@ index.html.ep
% layout 'default';
% title 'Welcome';
<h1>Welcome to the Mojolicious real-time web framework!</h1>

@@ unauthorized.html.ep
% layout 'default';
% title 'Unauthorized';
% if (param 'username') {
  <h1>Check your email</h1>
  <p>Check your email for a link to log in.</p>
% } else {
  <h1>Unauthorized</h1>
  <p>You must be logged in to access this page.</p>
  %= form_for 'login' => (method => 'POST') => begin
  %= hidden_field 'url' => $c->req->url->to_abs->to_string
  %= label_for username => 'Username'
  %= text_field 'username'
  %= submit_button 'Login'
  % end
% }

@@ layouts/default.html.ep
<!DOCTYPE html>
<html>
  <head><title><%= title %></title></head>
  <body><%= content %></body>
</html>
