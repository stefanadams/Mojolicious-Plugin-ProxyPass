package ProxyPass::Controller::ProxyPass;
use Mojo::Base 'Mojolicious::Controller', -signatures;

has default_url => '/proxypass';
has url => sub ($self) { $self->param('_URL') || $self->app->config->{proxy_pass}->{default_url} || $self->default_url };

sub auth_upstream ($self) {
  my $upstream = $self->proxy->upstream;
  my $auth_upstream = $self->stash->{config}->{auth_upstream} || [];
  return 1 unless grep { $_ eq $upstream->host_port } @$auth_upstream;
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

sub login ($self) {
  my $url = $self->url;
  my $redirect = $self->url_for('proxypass_logout')->query(_URL => $url);
  if (my $id = $self->proxy->login) {
    $self->render('proxypass/logged_in', id => $id, url => $url, logout => $redirect);
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
  %= checkbox 'admin'
</p>
<p>
  %= submit_button
</p>
% end

@@ proxypass/logged_in.html.ep
% layout 'default';

Logged in, <%= $id %>, <%= link_to 'proceed' => $url %><br />
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