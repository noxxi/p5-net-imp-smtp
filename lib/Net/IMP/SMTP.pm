use strict;
use warnings;

package Net::IMP::SMTP;
use Net::IMP qw(:DEFAULT IMP_DATA );
use Exporter 'import';

our $VERSION = '0.001';
our @EXPORT;

# create and export IMP_DATA_SMTP* constants
push @EXPORT, IMP_DATA( 'smtp',
    'command'    => +1,  # SMTP command
    'response'   => +2,  # response to SMTP command
    'greeting'   => +3,  # initial SMTP greeting
    'mail'       => -4,  # payload of DATA command
    'junk'       => -5,  # unexpected data, protocol error
);

use constant IMP_OFFSET_SMTP_EOMAIL => IMP_MAXOFFSET-1;
push @EXPORT, 'IMP_OFFSET_SMTP_EOMAIL';


__END__

=head1 NAME

Net::IMP::SMTP - interface for SMTP specific L<Net::IMP> plugins

=head1 DESCRIPTION

The Net::IMP::SMTP modules make it easier to write SMTP specific IMP plugins.

The following modules are currently implemented or planned:

=over 4

=item Net::IMP::SMTP::Base

This module provides the data type definitions for SMTP connection types.

=item Net::IMP::Adaptor::STREAM2SMTP

Using this module can adapt SMTP connection specific plugins into a simple
stream interface (IMP_DATA_STREAM)

=back

C<Net::IMP::SMTP> defines the following constants for SMTP specific data types

  IMP_DATA_SMTP_COMMAND    - command send from client to server
  IMP_DATA_SMTP_RESPONSE   - response from server to clients command
  IMP_DATA_SMTP_GREETING   - the initial greeting from the server
  IMP_DATA_SMTP_MAIL       - the mail, i.e. payload of the DATA command
  IMP_DATA_SMTP_JUNK       - data which are in violation of the SMTP protocol

Additionally a special offset IMP_OFFSET_SMTP_EOMAIL is defined which describes
the end of the current mail and not the end of the connection.

=head1 SEE ALSO

L<Net::IMP>

=head1 AUTHOR

Steffen Ullrich, <sullr@cpan.org>

=head1 COPYRIGHT

Copyright 2016 Steffen Ullrich

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
