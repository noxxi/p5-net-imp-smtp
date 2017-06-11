use strict;
use warnings;

package Net::IMP::SMTP::Example::StripInternalHeaders;
use base 'Net::IMP::SMTP::Base';
use fields qw(offset hbuf);
use Net::IMP 0.634;
use Net::IMP::SMTP;

my $MAXHEAD = 2**16; # maximum size of mail header

sub RTYPES { ( IMP_PASS, IMP_PREPASS, IMP_REPLACE ) }

sub new_analyzer {
    my ($factory,%args) = @_;
    my $analyzer = $factory->SUPER::new_analyzer(%args);
    $analyzer->{hbuf} = '';

    # we are only interested in data from client to server
    $analyzer->run_callback([IMP_PASS,1,IMP_MAXOFFSET]);
    return $analyzer;
}

# pass everything except MAIL
sub data {
    my ($self,$dir,$data,$offset,$type) = @_;

    $self->{offset}[$dir] = $offset if $offset;
    $self->{offset}[$dir] += length($data);

    return $self->run_callback([ IMP_PASS,$dir,$self->{offset}[$dir] ])
	if $type != IMP_DATA_SMTP_MAIL;

    if (!defined $self->{hbuf}) {
	# already done with header
	return $self->run_callback([ IMP_PASS,$dir,IMP_OFFSET_SMTP_EOMAIL ])
    }

    $self->{hbuf} .= $data;
    my $eoh = 
	$data eq '' ? length($self->{hbuf}) : 
	$self->{hbuf} =~m{\r?\n\r?\n}g ? $+[0] :
	undef;

    if (!defined $eoh) {
	return if length($self->{hbuf}) < $MAXHEAD; # need more data
	$self->{hbuf} = undef;
	return $self->run_callback([ IMP_DENY,$dir,"mail header too large" ]);
    }


    my $head = substr($self->{hbuf},0,$eoh,'');

    my $newbuf = '';
    while ($head =~m{^(
	(?: From|To|Cc|Subject|Message-Id|References|In-Reply-To|Reply-To|Resent-\w+|Content-type|Content-Transfer-Encoding )
	:
	[^\n]*
	(?: \n[ \t].* )*
	\n
    )}ximg) {
	$newbuf .= $1;
    }
    $newbuf .= $head =~m{(\r?\n)} ? $1:"\r\n";
    $newbuf .= $self->{hbuf};
    $self->{hbuf} = undef; # done with header

    return $self->run_callback(
	[ IMP_REPLACE,$dir,$self->{offset}[$dir],$newbuf ],
	[ IMP_PASS,$dir,IMP_OFFSET_SMTP_EOMAIL ],
    )
}


1;
__END__

=head1 NAME

Net::IMP::SMTP::Example::StripInternalHeaders - strip internal mail headers

=head1 DESCRIPTION

This module leaves only the common mail headers about sender, recipient, subject
etc and strips everything else including Received headers to hide some details
about the internal delivery process.

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
