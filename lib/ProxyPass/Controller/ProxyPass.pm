package ProxyPass::Controller::ProxyPass;
use Mojo::Base 'Mojolicious::Controller', -signatures;

has url => sub ($self) { $self->param('_URL') || $self->app->proxy->default_url };

sub login ($self) {
  my $url = $self->url;
  my $redirect = $self->url_for('proxy_pass_logout')->query(_URL => $url);
  if (my $login = $self->proxy->login) {
    $self->session(ProxyPass => $login);
    $self->render('proxy_pass/logged_in', url => $url, logout => $redirect);
  }
  else {
    $self->render('proxy_pass/login_form', url => $url);
  }
}

sub logout ($self) {
  my $url = $self->url;
  my $logout = $self->app->proxy->logout;
  $self->session(expires => 1);
  $self->render('proxy_pass/logged_out', url => $url);
}

1;

__DATA__
@@ proxy_pass/logged_in.html.ep
% layout 'default';

Logged in, <%= link_to 'proceed' => $url %><br />
To logout, go <%= link_to here => $logout %>

@@ proxy_pass/logged_out.html.ep
% layout 'default';

Logged out, try accessing <%= link_to $url => $url %>

@@ proxy_pass/login_form.html.ep
% layout 'default';

<%= $url %>
<%= form_for 'proxy_pass_login' => (method => 'POST') => begin %>
<%= hidden_field _URL => $url %>
<%= text_field 'username' %>
<%= password_field 'password' %>
<%= submit_button %>
<% end %>

@@ layouts/default.html.ep
<!DOCTYPE html>
<html>
  <head><title><%= title %></title></head>
  <body><%= content %></body>
</html>