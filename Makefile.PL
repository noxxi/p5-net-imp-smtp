use ExtUtils::MakeMaker;
require 5.10.0;
WriteMakefile(
    NAME => 'Net::IMP::SMTP',
    VERSION_FROM => 'lib/Net/IMP/SMTP.pm',
    LICENSE => 'perl',
    PREREQ_PM => {
	Net::IMP => 0.634,
    },
    META_MERGE => {
	resources => {
	    repository => 'https://github.com/noxxi/p5-net-imp-smtp',
	},
   },
);
