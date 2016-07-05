use strict;
use warnings;
use Test::More tests => 4;

for my $pkg (
    'Net::IMP::SMTP',
    'Net::IMP::SMTP::Base',
    'Net::IMP::Adaptor::STREAM2SMTP',
    'Net::IMP::SMTP::Example::StripInternalHeader',
) {
    if ( ! ref $pkg) {
	ok( eval "require $pkg",$pkg );
    } else {
	SKIP: {
	    ($pkg, my @dep) = @$pkg;
	    while (@dep) {
		my ($p,$v) = splice(@dep,0,2);
		skip "cannot load $p",1 if ! eval "require $p";
		if ($v) { 
		    no strict 'refs';
		    skip "$p wrong version",1 if ${ "${p}::VERSION" } <= $v; 
		}
	    }
	    ok( eval "require $pkg",$pkg );
	}
    }
}
	
