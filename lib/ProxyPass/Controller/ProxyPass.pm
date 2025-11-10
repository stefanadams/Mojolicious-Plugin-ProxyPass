package ProxyPass::Controller::ProxyPass;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use Mojo::JSON qw(encode_json decode_json);
use Mojo::URL;
use Mojo::Util qw(b64_decode b64_encode);

has default_url => '/proxypass';
has url => sub ($self) { Mojo::URL->new($self->param('_URL') || $self->app->config->{proxy_pass}->{default_url} || $self->default_url) };

sub auth_upstream ($self) {
  my $upstream = $self->proxy->upstream;
  my $auth_upstream = $self->stash->{config}->{auth_upstream} || [];
  ($auth_upstream) = grep { $_->url eq $upstream->url->host_port } map { ProxyPass::AuthUpstream->new($_) } @$auth_upstream;
  $self->stash('proxypass.authupstream' => $auth_upstream);
  return 1 unless $auth_upstream;
  $self->log->trace(sprintf 'auth_upstream %s%s', $auth_upstream, @$auth_upstream ? join ' ', ' args:', @$auth_upstream : '');
  $self->log->info(sprintf '[auth] [%s] %s', $self->session('ProxyPass'), $self->req->url->path) and return 1 if $self->session('ProxyPass');
  $self->redirect_to($self->url_for('proxypass_login')->query(_URL => $self->req->url->to_abs->to_string));
  return undef;
}

sub generate_token ($self) {
  return $self->reply->not_found unless $self->session('ProxyPassAdmin');
  if (my $id = $self->param('id')) {
    $self->log->info(sprintf '[%s] token generated for %s (%s)', $self->session('ProxyPassAdmin'), $id, $self->param('admin') ? 'admin' : 'non-admin');
    $self->render(text => $self->proxy->jwt->token($id, $self->param('admin')));
  }
  else {
    $self->render('proxypass/generate_token');
  }
}

sub idp ($self) {
  $self->proxy->login or return $self->reply->text_error(401 => 'Unauthorized: not logged in');
  my $url = $self->param('url') || $self->req->headers->referrer or return $self->reply->text_error(400 => 'Bad Request: missing url parameter');
  $url = Mojo::URL->new($url);
  my $claims = {
    id => $self->session('ProxyPass') || 'anonymous',
    url => $url->host,
  };
  my $jwt = $self->proxy->jwt->claims($claims)->token($claims->{id});
  warn $self->app->dumper($self->proxy->jwt->decode($jwt));
  $self->redirect_to($url->query({jwt => $jwt}));
}

sub idp_auth ($self) {
  warn $self->app->dumper({body => $self->req->body});
  my $claims = Mojo::JSON::Pointer->new(decode_json(b64_decode($self->req->body) || '{}'));
  warn $claims;
  my $callback = $claims->get('/callback') or return $self->reply->exception('Missing claims callback parameter');
  my $id = $claims->get('/id') or return $self->reply->exception('Missing claims id parameter');
  my $email = $claims->get('/email') || 1;
  if ($email) {
    $self->log->info(sprintf 'IdP email retrieval successful for %s from %s', $id, $self->tx->req->headers->header('X-Forwarded-For') || $self->tx->remote_address);
    my $jwt = $self->proxy->jwt->token($id, 0);
    $callback = Mojo::URL->new($callback)->query(jwt => $jwt);
    warn $callback;
    return $self->reply->ok;
  }
  else {
    $self->log->info(sprintf 'IdP email retrieval failed for %s from %s', $id, $self->tx->req->headers->header('X-Forwarded-For') || $self->tx->remote_address);
    return $self->reply->exception('Email claim missing from identity provider');
  }
}

sub idp_verify ($self) {
  return $self->reply->ok if $self->session('id');
  my $jwt = $self->param('jwt') or return $self->reply->exception('Bad Request: jwt parameter missing');
  my $id = $self->proxy->jwt->id($jwt) or return $self->reply->exception('Unauthorized: invalid token');
  $self->session(id => $id)->reply->ok;
}

sub login ($self) {
  my $url = $self->url;
  my $logout = $self->url_for('proxypass_logout')->query(_URL => $url);
  if (my $id = $self->proxy->login) {
    $self->render('proxypass/logged_in', id => $id, url => $url, logout => $logout);
  }
  else {
    $self->render('proxypass/login_form', url => $url);
  }
}

sub logout ($self) {
  my $url = $self->url;
  $self->session(expires => 1);
  $self->render('proxypass/logged_out', url => $url);
}

sub proxypass ($self) {
  my $map = $self->stash('map');
  $self->render(json => $map->writer->fetch);
}

sub verify_token ($self) {
  my $jwt = $self->param('jwt') or return $self->reply->exception('Bad Request: jwt parameter missing');
  my $hash = $self->proxy->jwt->decode($jwt) or return $self->reply->exception('Unauthorized: invalid token');
  $self->render(json => $hash);
}

1;

__DATA__
@@ proxypass/generate_token.html.ep
% layout 'default';

%= form_for 'proxypass_jwt' => (method => 'POST') => begin
<p>
  %= label_for id => 'ID'
  %= text_field 'id'
</p>
<p>
  %= label_for admin => 'Can generate JWTs?'
  %= check_box 'admin'
</p>
<p>
  %= submit_button
</p>
% end

@@ proxypass/logged_in.html.ep
% layout 'default';

Logged in, <%= $id %>, <%= link_to 'proceed' => $url->clone->query(jwt => $c->proxy->jwt->claims({host => $url->host})->token($id)) %><br />
% if (session 'ProxyPassAdmin') {
  To generate JWTs, go <%= link_to 'here' => 'proxypass_jwt' %>
% }
To logout, go <%= link_to here => $logout %>

@@ proxypass/logged_out.html.ep
% layout 'default';

Logged out, try accessing <%= link_to $url => $url %>

@@ proxypass/login_form.html.ep
% layout 'default';

<%= $url %>
%= form_for 'proxypass_login' => (method => 'POST') => begin
%= hidden_field _URL => $url
%= text_field 'jwt'
%= submit_button
% end

@@ layouts/default.html.ep
<!DOCTYPE html>
<html>
  <head><title><%= title %></title></head>
  <body><%= content %></body>
</html>