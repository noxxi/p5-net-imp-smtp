#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use Net::Inspect 0.328;
use Net::Inspect::Debug '%TRACE';
use Net::Inspect::L2::Pcap;
use Net::Inspect::L3::IP;
use Net::Inspect::L4::TCP;
use Net::Inspect::L7::SMTP;
use Net::PcapWriter 0.721;
use Net::Pcap qw(pcap_open_offline pcap_loop);
use Net::IMP 0.634;
use Net::IMP::Debug;
use Net::IMP::Cascade;
use Net::IMP::SMTP;


# interface we support in this program
my @rtypes = (
    IMP_PASS,
    IMP_PREPASS,
    IMP_DENY,
    IMP_REPLACE,
    IMP_LOG,
    IMP_ACCTFIELD,
    IMP_PAUSE,
    IMP_CONTINUE,
    IMP_FATAL,
);
my @interface = (
    [ IMP_DATA_SMTP, \@rtypes ],
);


sub usage {
    print STDERR <<USAGE;

filter SMTP connections from pcap file using Net::IMP::SMTP analyzer
$0 Options*  -r in.pcap -w out.pcap

Options:
  -h|--help               show usage
  -M|--module mod[=arg]   use Net::IMP module for connections
			  can be given multiple times for cascading modules
  -r|--read  in.pcap      input pcap file
  -w|--write out.pcap     output pcap file
  -d|--debug              debug mode
  -T|--trace T            Net::Inspect traces

USAGE
    exit(2);
}

my (@module,$infile,$outfile);
GetOptions(
    'M|module=s' => \@module,
    'r|read=s'   => \$infile,
    'w|write=s'  => \$outfile,
    'h|help'     => sub { usage() },
    'd|debug'    => \$DEBUG,
    'T|trace=s'  => sub { $TRACE{$_}=1 for split(m/,/,$_[1]) }
);

$Net::Inspect::Debug::DEBUG=$DEBUG;

$infile ||= '/dev/stdin';
my $err;
my $pcap_in = pcap_open_offline($infile,\$err) or die $err;
my $pcap_out = Net::PcapWriter->new( $outfile || \*STDOUT ) or die $!;


my @factory;
for my $module (@module) {
    $module eq '=' and next;
    my ($mod,$args) = $module =~m{^([a-z][\w:]*)(?:=(.*))?$}i
	or die "invalid module $module";
    eval "require $mod" or die "cannot load $module";
    my %args = $mod->str2cfg($args//'');
    my $factory = $mod->new_factory(%args) or
	croak("cannot create Net::IMP factory for $mod");
    push @factory, $factory;
}

my $imp_factory;
if (@factory == 1) {
    $imp_factory = $factory[0];
} elsif (@factory) {
    $imp_factory = Net::IMP::Cascade->new_factory(
	parts => \@factory
    ) or croak("cannot create factory from Net::IMP::Cascade");
}
if ($imp_factory) {
    warn "XXXX $imp_factory @interface";
    @interface = $imp_factory->get_interface(@interface) or
	Carp::croak("cannot use modules - wrong interface");
}

my $cw  = ConnWriter->new($pcap_out,$imp_factory);
my $smtp = Net::Inspect::L7::SMTP->new($cw);
my $tcp = Net::Inspect::L4::TCP->new($smtp);
my $raw = Net::Inspect::L3::IP->new($tcp);
my $pc  = Net::Inspect::L2::Pcap->new($pcap_in,$raw);

my $time;
my @tcpconn;
pcap_loop($pcap_in,-1,sub {
    my (undef,$hdr,$data) = @_;
    if ( ! $time || $hdr->{tv_sec}-$time>10 ) {
	$cw->expire($time = $hdr->{tv_sec});
    }
    return $pc->pktin($data,$hdr);
},undef);

for(@tcpconn) {
    $_ or next;
    $_->shutdown(0);
    $_->shutdown(1);
}


package ConnWriter;
use base 'Net::IMP::Filter';
use Net::IMP;
use Net::IMP::SMTP;

sub new {
    my ($class,$pcap,$imp) = @_;
    my $self = $class->SUPER::new($imp,
	$pcap ? (pcap => $pcap):(), 
	expire => 0, 
	meta => undef,
	mbuf => '',
    );
    return $self;
}

sub new_connection {
    my ($self,$meta) = @_;
    $self->{meta} = $meta;
    my $imp = $self->{imp}
	&& $self->{imp}->new_analyzer(meta => $meta);
    my $pcap = $self->{pcap}->tcp_conn(
	$meta->{saddr}, $meta->{sport},
	$meta->{daddr}, $meta->{dport},
    );

    # collect open connections to destroy them before pcap writer
    # gets destroyed
    @tcpconn = grep { $_ } @tcpconn;
    push @tcpconn,$pcap;
    Scalar::Util::weaken( $tcpconn[-1] );

    return $self->new($pcap,$imp);
}

BEGIN {
    for (
	[ 'greeting',  1, IMP_DATA_SMTP_GREETING ],
	[ 'command',   0, IMP_DATA_SMTP_COMMAND ],
	[ 'response',  1, IMP_DATA_SMTP_RESPONSE ],
	[ 'mail_data', 0, IMP_DATA_SMTP_MAIL ],
    ) {
	my ($name,$dir,$type) = @$_;
	no strict 'refs';
	*$name = sub {
	    my ($self,$data) = @_;
	    print STDERR "[$type] $data\n";
	    $self->SUPER::in($dir,$data,$type);
	    return length($data);
	};
    }
}


sub auth_data {
    die "not yet implemented"
}

sub fatal { warn "fatal: @_[1..$#_]\n" }

sub out {
    my ($self,$dir,$data,$type) = @_;
    if ($type == IMP_DATA_SMTP_MAIL) {
	$self->{mbuf} .= $data;
	$self->{mbuf} =~s{\r?\n}{\r\n}g;
	$self->{mbuf} =~s{\n\.}{\n..}g;
	if ($self->{mbuf} =~m{(?:.\n|\r)\z}s) {
	    $data = substr($self->{mbuf},0,$-[0],'');
	} else {
	    $data = $self->{mbuf};
	    $self->{mbuf} = '';
	}
    } elsif ($self->{mbuf} ne '') {
	$self->{mbuf} .= "\r\n" if substr($data,-1,1) ne "\n";
	$self->{mbuf} .= ".\r\n";
	$self->{pcap}->write(0,$self->{mbuf});
	$self->{mbuf} = '';
    }
    $self->{pcap}->write($dir,$data);
}

sub expire {
    my ($self,$expire) = @_;
    return $self->{expire} && $time>$self->{expire};
}

sub log {
    my ($self,$level,$msg,$dir,$offset,$len) = @_;
    print STDERR "[$level] $msg\n";
}


