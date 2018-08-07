use 5.008000;
use ExtUtils::MakeMaker;
use List::Util qw/uniq/;
use Cwd qw/abs_path/;
use File::Basename qw/dirname/;

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
    clean             => {
        # this file is created before building, and should be installed.. but cleaned when 'make clean' is run.
        FILES => 'lib/Crypt/Sodium/BuildVersion.pm',
    },
);

my $i = 0;
if (scalar(keys %$c) > 0) {
    # pkg-config situation works out to a 4
    if ($c->{modversion}) {
        $i = 4;
        my ($major, $minor, $revision) = split(/\./, $c->{modversion});
        $config{DEFINE} .= " -DP5CS_LIBMAJ=$major -DP5CS_LIBMIN=$minor -DP5CS_LIBREV=$revision -DP5CS_LIBVER=" . '\"' . $c->{modversion} . '\"';
        write_ver_file($c->{modversion});
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
        if (-f "/usr/local/Cellar/libsodium/$c->{modversion}/include/sodium.h") {
            $i += 3;
            $c->{libdir} = "-lsodium -L/usr/local/Cellar/libsodium/$c->{modversion}t/lib";            
            $c->{includedir} = "/usr/local/Cellar/libsodium/$c->{modversion}/include";
            my ($major, $minor, $revision) = split(/\./, $c->{modversion});
            # far fetched but..
            $config{DEFINE} .= " -DP5CS_LIBMAJ=$major -DP5CS_LIBMIN=$minor -DP5CS_LIBREV=$revision -DP5CS_LIBVER=" . '\"' . $c->{modversion} . '\"';
            write_ver_file($c->{modversion});
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
        
        $c->{modversion} = '1.0.8';
        write_ver_file();
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

$config{DEFINE} .= " " . extra_define_flags($c->{modversion});

print "\n";

WriteMakefile(%config);

if ($i >= 3) {
    print "\n[ :D ] Found libsodium $c->{modversion} in $c->{libdir}";
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

sub extra_define_flags {
    my ($lsv) = @_;
    
    my @edefs;
    # version 1.0.9
    # introduced crypto_pwhash_argon2i
    push(@edefs, "-D" . enable_feature(
        '1.0.9',
        P5CS_CPWH => "crypto_pwhash namespace introduced for password hashing functionality", 
    ));
    # introduced "speed record" BLAKE2b and state
    push(@edefs, "-D" . enable_feature(
        '1.0.9',
        P5CS_GH_BLAKE2B => "crypto_generichash_blake2bxx functionality", 
    ));
    # introduced "speed record" BLAKE2b and state
    push(@edefs, "-D" . enable_feature(
        '1.0.9',
        P5CS_GH_BLAKE2B => "crypto_generichash_blake2bxx functionality", 
    ));
    
    # version 1.0.12
    # introduced multiple _keygen() variants for the different algorithms
    push(@edefs, "-D" . enable_feature(
        '1.0.12',
        P5CS_KG_VAR => "xx_keygen and xx_keypair variants present for various algorithms",
    ));
    # introduced ed25519ph; multi-part signature API
    push(@edefs, "-D" . enable_feature(
        '1.0.12',
        P5CS_ED25519PH => "Ed25519ph multi-part signature algorithm functionality",
    ));
    # crypto_kdf present in 1.0.12
    push(@edefs, "-D" . enable_feature(
        '1.0.12',
        P5CS_CKDF => "crypto_kdf namespace available for key derivation functionality",
    ));
    # randombytes_buf_deterministic in 1.0.12
    push(@edefs, "-D" . enable_feature(
        '1.0.12',
        P5CS_DRNG => "randombytes_buf_deterministic psuedo random number generator",
    ));

    return join(' ', @edefs);    
}

sub enable_feature {
    my ($reqver, $def, $desc) = @_;

    my $enable;
    if (vercmp($c->{modversion}, $reqver)) {
        print "[ +++ ] feature $def - ENABLED";
        $enable = 1;
    } else {
        print "[ --- ] feature $def - DSABLED";
    }
    if ($desc) {
        print " - $desc";
    }
    print " - req v$reqver or higher; have v$c->{modversion}\n";
    
    return $enable ? $def : undef;
}

sub vercmp {
    my ($ay, $be) = map { join('', map { $_ * 100 } split(/\./, $_)) } @_;
    if ($ay > $be) {
        return 1;
    }
    return undef;
}

sub write_ver_file {
    my ($lsv) = @_;
    $lsv //= '1.0.8';
    my ($major, $minor, $revision) = split(/\./, $lsv);
    my $dist_path = dirname(abs_path(__FILE__));
    if (-d "$dist_path/lib/Crypt/Sodium") {
        # we're in the right place.
        open my $fh, '>', "$dist_path/lib/Crypt/Sodium/BuildVersion.pm";
        print $fh "package Crypt::Sodium::BuildVersion;\n";
        print $fh 'our $VERSION = ' . "'v$lsv';\n";
        print $fh 'our $MAJOR = ' . $major . ";\n";
        print $fh 'our $MINOR = ' . $minor . ";\n";
        print $fh 'our $REVISION = ' . $revision . ";\n";
        print $fh "1;\n";
        close $fh;
    }
}
