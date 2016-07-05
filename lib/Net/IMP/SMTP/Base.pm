use strict;
use warnings;

package Net::IMP::SMTP::Base;
use base 'Net::IMP::Base';
use fields qw(dispatcher pos);
use Net::IMP;
use Carp 'croak';


# just define a typical set, maybe need to be redefined in subclass
sub RTYPES { 
    my $factory = shift;
    return (IMP_PASS, IMP_PREPASS, IMP_REPLACE, IMP_DENY, IMP_LOG) 
}

sub INTERFACE {
    my $factory = shift;
    my @rt = $factory->RTYPES;
    return (
	[ IMP_DATA_SMTP, \@rt ],
	[ IMP_DATA_STREAM, \@rt, 'Net::IMP::Adaptor::STREAM2SMTP' ],
    );
}

# we can overide data to handle the types directly, but per default we
# dispatch to seperate methods
sub data {
    my ($self,$dir,$data,$offset,$type) = @_;

    $self->{pos}[$dir] = $offset if $offset;
    $self->{pos}[$dir] += length($data);

    my $disp = $self->{dispatcher} ||= {
	IMP_DATA_SMTP_GREETING+0  => [
	    undef,
	    $self->can('greeting'),
	],
	IMP_DATA_SMTP_COMMAND+0  => [
	    $self->can('command'),
	    undef,
	],
	IMP_DATA_SMTP_RESPONSE+0  => [
	    undef,
	    $self->can('response'),
	],
	IMP_DATA_SMTP_MAIL+0 => [ 
	    $self->can('mail_data'),
	    undef,
	],
	IMP_DATA_SMTP_JUNK+0 => $self->can('junk_data')
    };
    my $sub = $disp->{$type+0} or croak("cannot dispatch type $type");
    if ( ref($sub) eq 'ARRAY' ) {
	$sub = $sub->[$dir] or croak("cannot dispatch type $type dir $dir");
	$sub->($self,$data,$offset);
    } else {
	$sub->($self,$dir,$data,$offset);
    }
}

sub offset {
    my ($self,$dir) = @_;
    return $self->{pos}[$dir] // 0;
}


###########################################################################
# public interface
# most of these methods need to be implemented in subclass
###########################################################################

for my $subname ( 
    'greeting',        # ($self,$msg)
    'command',         # ($self,$command)
    'response',        # ($self,$response)
    'mail_data',       # ($self,$data,[$offset])
    'junk_data',       # ($self,$dir,$data,[$offset])
) {
    no strict 'refs';
    *$subname = sub { croak("$subname needs to be implemented in $_[0]") }
}


1;
__END__

=head1 NAME 

Net::IMP::SMTP::Base - base class for SMTP specific IMP plugins

=head1 SYNOPSIS

    package mySMTPAnalyzer;
    use base 'Net::IMP::SMTP::Base';

    # implement methods for the various parts of an HTTP traffic
    sub greeting ...
    sub command ...
    sub response ...
    sub mail_data ...
    sub junk_data ...

=head1 DESCRIPTION

Net::IMP::SMTP::Base is a base class for SMTP request specific IMP plugins.
It provides a way to use such plugins in SMTP aware applications but with the
help of L<Net::IMP::Adaptor::STREAM2SMTP> also in applications using only an
untyped data stream.

Return values are the same as in other IMP plugins. This means that
IMP_MAXOFFSET describes the end of the connection. To describe the end of the
current mail when within the DATA command IMP_OFFSET_SMTP_EOMAIL can be used.

You can either redefine the C<data> method (common to all IMP plugins) or use
the default implementation, which dispatches to various method based on the
type of the received data. In the latter case you need to implement:

=over 4

=item greeting($self,$msg)

This method gets the initial greeting inside the mail dialog.

=item command($self,$cmd)

This method gets the command from the client.

=item response($self,$msg)

This method gets the response from the server to the clients command.

=item mail_data($self,$data,[$offset])

This method is called for parts of the mail, i.e. within the DATA command.
For the final part it will be called with C<$data> set to C<''>.

=item junk_data($self,$dir,$data,[$offset])

This method is called on protocol violations, i.e. junk data.

=back

If you use the default implementation of C<data> you can also use the method
C<offset(dir)> to find out the current offset (e.g. position in byte stream
after the given data). 

Also an C<RTYPES> method should be implemented for the factory object and
return a list of the supported return types. These will be used to construct
the proper C<interface> method.
