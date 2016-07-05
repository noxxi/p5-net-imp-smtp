use strict;
use warnings;

package Net::IMP::SMTP::Example::StripInternalHeaders;
use base 'Net::IMP::SMTP::Base';
use fields qw(offset head);
use Net::IMP;
use Net::IMP::SMTP;

my $MAXHEAD = 2**16; # maximum size of mail header

sub RTYPES { ( IMP_PASS, IMP_PREPASS, IMP_REPLACE ) }
sub new_analyzer {
    my ($factory,%args) = @_;
    my $analyzer = $factory->SUPER::new_analyzer(%args);
    $analyzer->{head} = '';

    # we are only interested in data from client to server
    $analyzer->run_callback([IMP_PASS,1,IMP_MAXOFFSET]);
    return $analyzer;
}

# pass everything except MAIL
sub data {
    my ($self,$dir,$data,$offset,$type) = @_;

    $self->{offset}[$dir] = $offset if defined $offset;
    $self->{offset}[$dir] += length($data);

    return $self->run_callback([ IMP_PASS,$dir,$offset ])
	if $type != IMP_DATA_SMTP_MAIL;

    if (!defined $self->{head}) {
	# already done with header
	return $self->run_callback([ IMP_PASS,$dir,IMP_OFFSET_SMTP_EOMAIL ])
    }

    $self->{head} .= $data;
    my $eoh = 
	$data eq '' ? length($self->{head}) : 
	$self->{head} =~m{\r?\n\r?\n}g ? $+[0] :
	undef;

    if (!defined $eoh) {
	return if length($self->{head}) < $MAXHEAD; # need more data
	$self->{head} = undef;
	return $self->run_callback([ IMP_DENY,$dir,"mail header too large" ]);
    }

    my $head = substr($self->{head},0,$eoh);
    my $offset_eohead = $self->{offset}[$dir] 
	- length($self->{head}) + length($head);
    $self->{head} = undef;

    my $newhead = '';
    while ($head =~m{^(
	(?: From|To|Cc|Subject|Message-Id|References|In-Reply-To|Reply-To|Resent-\w+ )
	:
	[^\n]*
	(?: \n[ \t].* )*
	\n
    )}xig) {
	$newhead .= $_;
    }
    $newhead .= $head =~m{(\r?\n)} ? $1:"\r\n";

    return $self->run_callback(
	[ IMP_REPLACE,$dir,$offset_eohead,$newdata ],
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
