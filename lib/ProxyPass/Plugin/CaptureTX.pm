package ProxyPass::Plugin::CaptureTX;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

use Mojo::File qw(path);
use Mojo::Home;

has tx_dir  => sub { Mojo::Home->new->detect->child('tx') };
has skip_cb => sub { sub {} };

sub register {
  my ($self, $app, $conf) = @_;

  my $path = path($conf->{path}) if $conf->{path};
  $self->tx_dir(path($conf->{path})) if $path;
  return unless -d $self->tx_dir;
  $app->log->debug('Capturing Transactions');
  $self->skip_cb($conf->{skip_cb}) if $conf->{skip_cb};
  $app->hook(after_build_tx => sub { $self->_capture($_[1], $_[0]) });
  $app->helper(capture_tx => sub { $self->_capture($_[0]->app, $_[1]) });
}

# Capture real requests for replaying later
# $ nc localhost 3000 < tx_dir/abc123
sub _capture ($self, $app, $tx) {
  my $assets = {};
  $tx->on(connection => sub ($tx, $connection) {
    my $asset = $assets->{$connection} //= Mojo::Asset::File->new(cleanup => 0, path => $self->tx_dir);
    my $stream = Mojo::IOLoop->stream($connection);
    $stream->on(read => sub ($stream, $bytes) {
      return if $self->skip_cb->($app, $tx, $stream, $bytes);
      $app->log->debug(sprintf '[%s] got %d bytes', $connection, length($bytes));
      $asset->add_chunk($bytes);
    });
    $stream->on(close => sub ($tx) {
      $app->log->debug(sprintf '[%s] captured %d-byte tx', $connection, $asset->size);
      delete $assets->{$connection};
    });
  });
}

1;