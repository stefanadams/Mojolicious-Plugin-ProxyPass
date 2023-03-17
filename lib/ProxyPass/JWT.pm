package ProxyPass::JWT;
use Mojo::Base -base, -signatures;

use Mojo::JWT;

has jwt_secret  => __FILE__;
has jwt_timeout => 600;
has jwt         => sub ($self) { Mojo::JWT->new(secret => $self->jwt_secret) };

sub id ($self, $token) { $self->jwt->decode($token)->{ProxyPass} }

sub token ($self, $id, $jwt_timeout=undef) {
  my $expires = time + ($jwt_timeout // $self->jwt_timeout);
  my $claims  = {ProxyPass => $id};

  return $self->jwt->expires($expires)->claims($claims)->encode;
}

sub url ($self, $url, $token) { Mojo::URL->new($url)->query({proxypass => $token}) }

1;
