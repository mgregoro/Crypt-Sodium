use 5.008000;
use ExtUtils::MakeMaker;
use List::Util qw/uniq/;
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
    LIBS              => [], # e.g., '-lm'
    DEFINE            => '-std=gnu99 -Wno-pointer-sign', # e.g., '-DHAVE_SOMETHING'
    INC               => '', # e.g., '-I. -I/usr/include/other'
    # Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);

my $i = 0;
if (scalar(keys %$c) > 0) {
    # pkg-config situation works out to a 4
    if ($c->{modversion}) {
        $i = 4;
        my ($major, $minor, $revision) = split(/\./, $c->{modversion});
        $config{DEFINE} .= " -DP5CS_LIBMAJ=$major -DP5CS_LIBMIN=$minor -DP5CS_LIBREV=$revision -DP5CS_LIBVER=" . '\"' . $c->{modversion} . '\"';
    }
    
    if ($c->{libdir}) {
        $c->{libdir} = "-lsodium -L$c->{libdir}";
    }
} else {
    # if this file exists, let's make some assumptions
    if (-f "/usr/local/include/sodium.h") {
        $c->{includedir} = "/usr/local/include";
        $c->{libdir} = "-lsodium -L/usr/local/lib";
    } 
    
    # let's see if we can find a better (admittedly self-serving) bet...
    if (-d "/usr/local/Cellar/libsodium") {
        # just build against the newest homebrew libsodium this situation should work out to '3'. 
        $c->{modversion} = (sort {$b <=> $a} `ls /usr/local/Cellar/libsodium`)[0];
        if (-f "/usr/local/Cellar/libsodium/$newest/include/sodium.h") {
            $i += 3;
            $c->{libdir} = "-lsodium -L/usr/local/Cellar/libsodium/$newest/lib";            
            $c->{includedir} = "/usr/local/Cellar/libsodium/$newest/include";
            my ($major, $minor, $revision) = split(/\./, $c->{modversion});
            # far fetched but..
            $config{DEFINE} .= " -DP5CS_LIBMAJ=$major -DP5CS_LIBMIN=$minor -DP5CS_LIBREV=$revision -DP5CS_LIBVER=" . '\"' . $c->{modversion} . '\"';
        }
    } else { 
        # Alien::Sodium (as of Jun 11 2018) supplies 1.0.8 anyway, so if we find it, just make sure we have the 
        # environment set up to use it if nothing better was found.  $i should work out to 2.
        eval "use Alien::Sodium;";
        unless ($@) {
            $i = 2;
            $c->{libdir} = join(' ', uniq(split(/ /, Alien::Sodium->libs)));
            $c->{includedir} = join(' ', uniq(split/ /, Alien::Sodium->cflags));
        }
        
        $config{DEFINE} .= " -DP5CS_LIBMAJ=1 -DP5CS_LIBMIN=0 -DP5CS_LIBREV=8 -DP5CS_LIBVER=" . '\"1.0.8\"';
    }
}

if ($c->{libdir}) {
    $config{LIBS}->[0] = $c->{libdir};
} else {
    $config{LIBS}->[0] = "-lsodium";
}

if ($c->{includedir}) {
    $config{INC} = "-I. -I$c->{includedir}";
} else {
    $config{INC} = "-I.";
}

WriteMakefile(%config);

if ($i >= 3) {
    print "\n[ :D ] Found libsodium $c->{modversion} in $c->{libdir}; headers in $c->{includedir}";
    if ($i == 3) {
        print " .. using unconventional means.";
    } elsif ($i == 4) {
        print " .. using pkg-config.";
    }
    print "\n";
    print "Please run 'make' and 'make test' to build Crypt::Sodium\n\n";
} elsif ($i == 2) {
    print "\n[ :| ] Found Alien::Sodium -- Assuming it provides libsodium v1.0.8\n";
    print "Please run 'make' and 'make test' to build Crypt::Sodium\n\n";
} else {
    print "\n[ :| ] Couldn't find pkg-config or pkg-config info for libsodium... assuming minimum v1.0.8\n";
    if ($c->{includedir}) {
        print "Please run 'make' and 'make test' to build Crypt::Sodium\n\n";
    } else {
        print "If you're sure you have libsodium 1.0.8 or higher installed, please run 'make' and 'make test' to build Crypt::Sodium\n\n";
    }
}
