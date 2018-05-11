use 5.008000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $c = {};
chomp(my $pc = `which pkg-config`);
if ($pc) {
    chomp( $c->{includedir} = `$pc --variable includedir libsodium` );
    chomp( $c->{libdir} = `$pc --variable libdir libsodium` );
    chomp( $c->{modversion} = `$pc --modversion libsodium` );
}

my %config = (
    NAME              => 'Crypt::Sodium',
    VERSION_FROM      => 'lib/Crypt/Sodium.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/Sodium.pm', # retrieve abstract from module
       AUTHOR         => 'Michael Gregorowicz <mike@mg2.org>') : ()),
    LIBS              => ['-lsodium'], # e.g., '-lm'
    DEFINE            => '-std=gnu99 -Wno-pointer-sign', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    # Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);

my $i = 0;
if (scalar(keys %$c) > 0) {
    $c->{includedir} && $i++ and $config{INC} = "-I. -I$c->{includedir}";
    $c->{libdir} && $i++ and $config{LIBS} = "-L$c->{libdir} -lsodium";
    if ($c->{modversion}) {
        $i++;
        my ($major, $minor, $revision) = split(/\./, $c->{modversion});
        $config{DEFINE} .= " -DP5CS_LIBMAJ=$major -DP5CS_LIBMIN=$minor -DP5CS_LIBREV=$revision -DP5CS_LIBVER=" . '\"' . $c->{modversion} . '\"';
    }
} else {
    $config{DEFINE} .= " -DP5CS_LIBMAJ=1 -DP5CS_LIBMIN=0 -DP5CS_LIBREV=8 -DP5CS_LIBVER=" . '\"1.0.8\"';
}

WriteMakefile(%config);

if ($i == 3) {
    print "\n[ :D ] Found libsodium $c->{modversion} in $c->{libdir}; headers in $c->{includedir}\n\n";
} else {
    print "\n[ :| ] Couldn't find pkg-config or pkg-config info for libsodium... assuming minimum v1.0.8\n\n";
}