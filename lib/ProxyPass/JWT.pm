package ProxyPass::JWT;
use Mojo::Base -base, -signatures;

use Mojo::JWT;

has jwt_secret  => __FILE__;
has jwt_timeout => 600;
has jwt         => sub ($self) {
  Mojo::JWT->new(expires => time + $self->jwt_timeout, secret => $self->jwt_secret)
};

sub id ($self, $token) {
  $self->jwt->decode($token)->{ProxyPass};
}

sub url ($self, $url, $id) {
  Mojo::URL->new($url)->query({proxypass => $self->jwt->claims({ProxyPass => $id})->encode});
};

1;
